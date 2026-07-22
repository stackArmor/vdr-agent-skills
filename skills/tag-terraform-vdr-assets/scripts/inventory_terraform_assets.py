#!/usr/bin/env python3
"""Read-only inventory of CIS Foundations-mapped Terraform resource/module blocks.

The script intentionally does not parse state, plans, tfvars, or .terraform.
It uses a conservative HCL block scanner plus a versioned regex allowlist. Its
output is a review queue, not authorization to add provider arguments.
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path


DEFAULT_MAP = Path(__file__).resolve().parent.parent / "references" / "cis-asset-map.json"
MODULE_PROVIDER_GATES = {
    "gcp": ("(?=.*(?:gcp|google))", re.compile(r"(?:gcp|google)", re.I)),
    "aws": ("(?=.*aws)", re.compile(r"aws", re.I)),
    "azure": ("(?=.*(?:azure|azurerm))", re.compile(r"(?:azure|azurerm)", re.I)),
}
BLOCK_START = re.compile(
    r'^\s*(resource|module)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{'
)
ATTR = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=')
SOURCE = re.compile(r'^\s*source\s*=\s*"([^"]+)"', re.MULTILINE)


def load_map(path):
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("schema_version") != 1:
        raise ValueError(f"unsupported asset-map schema: {data.get('schema_version')!r}")
    for group in ("resources", "module_hints"):
        for entry in data.get(group, []):
            pattern = entry["pattern"]
            if group == "module_hints":
                gate, provider_regex = MODULE_PROVIDER_GATES[entry["provider"]]
                if not pattern.startswith(gate):
                    raise ValueError(f"module hint lacks {entry['provider']} provider gate: {pattern}")
                pattern = pattern[len(gate) :]
                entry["_provider_regex"] = provider_regex
            entry["_regex"] = re.compile(pattern)
    return data


def terraform_files(root):
    if root.is_file():
        if root.suffix != ".tf":
            raise ValueError(f"not a Terraform .tf file: {root}")
        yield root
        return
    for path in sorted(root.rglob("*.tf")):
        if any(part in {".terraform", ".git"} for part in path.parts):
            continue
        yield path


def scan_line(line, state):
    """Return brace delta outside strings/comments/heredocs."""
    if state["heredoc"]:
        if line.strip() == state["heredoc"]:
            state["heredoc"] = None
        return 0

    delta = 0
    i = 0
    quote = state["quote"]
    block_comment = state["block_comment"]
    while i < len(line):
        pair = line[i : i + 2]
        ch = line[i]
        if block_comment:
            if pair == "*/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if pair == "/*":
            block_comment = True
            i += 2
            continue
        if pair == "//" or ch == "#":
            break
        if ch in ('"', "'"):
            quote = ch
            i += 1
            continue
        if ch == "{":
            delta += 1
        elif ch == "}":
            delta -= 1
        i += 1

    state["quote"] = quote
    state["block_comment"] = block_comment
    if not quote and not block_comment:
        heredoc = re.search(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)", line)
        if heredoc:
            state["heredoc"] = heredoc.group(1)
    return delta


def iter_blocks(path):
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    i = 0
    while i < len(lines):
        match = BLOCK_START.match(lines[i])
        if not match:
            i += 1
            continue
        state = {"quote": None, "block_comment": False, "heredoc": None}
        depth = 0
        end = i
        while end < len(lines):
            depth += scan_line(lines[end], state)
            if end > i and depth <= 0:
                break
            end += 1
        if depth != 0:
            raise ValueError(f"unterminated {match.group(1)} block at {path}:{i + 1}")
        yield {
            "kind": match.group(1),
            "type": match.group(2),
            "name": match.group(3),
            "line": i + 1,
            "text": "".join(lines[i : end + 1]),
        }
        i = end + 1


def top_level_attributes(block_text):
    attrs = set()
    state = {"quote": None, "block_comment": False, "heredoc": None}
    depth = 0
    for line_number, line in enumerate(block_text.splitlines(keepends=True)):
        if line_number and depth == 1:
            match = ATTR.match(line)
            if match:
                attrs.add(match.group(1))
        depth += scan_line(line, state)
    return sorted(attrs)


def first_match(value, entries):
    for entry in entries:
        provider_regex = entry.get("_provider_regex")
        if provider_regex and not provider_regex.search(value):
            continue
        if entry["_regex"].search(value):
            return entry
    return None


def public_entry(entry):
    return {key: value for key, value in entry.items() if not key.startswith("_")}


def inventory(root, mapping, include_unknown=False, provider=None):
    rows = []
    for path in terraform_files(root):
        display_path = str(path.relative_to(root)) if root.is_dir() else path.name
        for block in iter_blocks(path):
            attrs = top_level_attributes(block["text"])
            if block["kind"] == "resource":
                entry = first_match(block["type"], mapping["resources"])
                address = f'{block["type"]}.{block["name"]}'
                source = None
                status = "eligible" if entry else "unknown"
            else:
                source_match = SOURCE.search(block["text"])
                source = source_match.group(1) if source_match else ""
                hint_value = f'{source} {block["type"]}'
                entry = first_match(hint_value, mapping["module_hints"])
                address = f'module.{block["type"]}'
                status = "module-review" if entry else "unknown"

            if not entry and not include_unknown:
                continue
            if provider and entry and entry["provider"] != provider:
                continue
            if provider and not entry:
                inferred = block["type"].split("_", 1)[0]
                wanted_prefix = {"gcp": "google", "aws": "aws", "azure": "azurerm"}[provider]
                if inferred != wanted_prefix:
                    continue

            info = public_entry(entry) if entry else {
                "provider": "unknown",
                "category": "unknown",
                "cis": [],
                "tag_surface": "unknown",
                "scope_carrier": False,
                "rationale": "No conservative CIS asset-map match.",
            }
            rows.append({
                "address": address,
                "block_kind": block["kind"],
                "resource_type": block["type"] if block["kind"] == "resource" else None,
                "module_source": source,
                "file": display_path,
                "line": block["line"],
                "status": status,
                "provider": info["provider"],
                "category": info["category"],
                "cis": info["cis"],
                "tag_surface": info["tag_surface"],
                "scope_carrier": info.get("scope_carrier", False),
                "top_level_metadata": [name for name in attrs if name in {"labels", "tags", "user_labels"}],
                "rationale": info["rationale"],
            })
    return rows


def render_table(rows):
    columns = ["address", "provider", "category", "cis", "surface", "location"]
    values = []
    for row in rows:
        values.append([
            row["address"],
            row["provider"],
            row["category"],
            ", ".join(row["cis"]) or "-",
            row["tag_surface"],
            f'{row["file"]}:{row["line"]}',
        ])
    widths = [len(column) for column in columns]
    for value in values:
        widths = [max(old, len(item)) for old, item in zip(widths, value)]
    print("  ".join(column.ljust(width) for column, width in zip(columns, widths)))
    print("  ".join("-" * width for width in widths))
    for value in values:
        print("  ".join(item.ljust(width) for item, width in zip(value, widths)))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Terraform root directory or one .tf file")
    parser.add_argument("--map", dest="map_path", type=Path, default=DEFAULT_MAP)
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument("--provider", choices=("gcp", "aws", "azure"))
    parser.add_argument("--include-unknown", action="store_true")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if not root.exists():
        parser.error(f"path does not exist: {root}")
    try:
        mapping = load_map(args.map_path.resolve())
        rows = inventory(root, mapping, args.include_unknown, args.provider)
    except (OSError, ValueError, json.JSONDecodeError, re.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps({
            "schema_version": 1,
            "root": str(root),
            "benchmarks": mapping["benchmarks"],
            "assets": rows,
        }, indent=2, sort_keys=True))
    else:
        render_table(rows)
        counts = Counter(row["status"] for row in rows)
        summary = ", ".join(f"{key}={counts[key]}" for key in sorted(counts)) or "none"
        print(f"\nReview queue: {len(rows)} blocks ({summary}). Read-only; no files changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
