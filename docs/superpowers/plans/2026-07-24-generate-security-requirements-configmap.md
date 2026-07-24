# generate-security-requirements-configmap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the `generate-security-requirements-configmap` skill that derives per-component CR/IR/AR vectors from system, agency, and component security objectives, emits the `vdr-fedramp` ConfigMap plus justification JSONs, and deprecates `generate-vdr-configmap`.

**Architecture:** A new skill directory under `skills/` (mirrored byte-identical under `.agents/skills/`) containing a SKILL.md workflow, a reference guide, three stdlib-only Python scripts (inventory collector, deterministic derivation math, validation gate), and a fictional example ConfigMap. Unit tests live at repo root `tests/` (not mirrored) using stdlib `unittest`. The spec is `docs/superpowers/specs/2026-07-24-security-requirements-configmap-design.md` — read it if a requirement here seems ambiguous.

**Tech Stack:** Python 3.8+ standard library only; `unittest`; Kubernetes ConfigMap YAML consumed by the sibling `trivy-plugin-vdr` Go plugin (no plugin changes).

## Global Constraints

- Python scripts: `python3 >= 3.8`, **standard library only** — no pip installs, no PyYAML.
- Scripts may execute only `kubectl get` and `kubectl config`; never exec/apply/label/patch/edit/delete.
- `skills/<name>/` and `.agents/skills/<name>/` must be byte-identical after every task that touches skill files. Sync with `rsync -a --delete` and verify with `diff -r`.
- **No real product, vendor, or agency names** anywhere in skill files — generic system-type language only (e.g. "project & portfolio management SaaS").
- Label grammar: `cr-[lmh]_ir-[lmh]_ar-[lmh]` (dot-free; dots are reserved by the plugin for the legacy trace grammar). Objective order in vectors is always C, I, A; levels order L < M < H.
- Closed breakout category list (exact tokens): `agency-endpoint-delivery`, `cross-system-trust-anchor`, `shared-csp-infrastructure`.
- `humanReviewCompleted` is always emitted `"false"`, comment-fenced, never set true by tooling, and its value is never printed by any script or report.
- Envelope math: `envelope(o) = min(sso(o), aso(o))`; `final(o) = min(cso(o), envelope(o))` unless a valid breakout restores `final(o) = cso(o)`. A breakout is only valid when `cso(o) > envelope(o)`.
- A breakout assignment must not be `high` confidence (it always needs a manual-review item; `high` requires an empty `manualReview` list).
- Commit messages: plain, present-tense, written as if authored by the repository owner. Never reference AI tools or assistants in any commit message.
- Do not bump plugin.json/marketplace.json versions or tag a release — that is the operator's call after review.

---

### Task 1: Land the uncommitted working-tree foundation

The working tree already contains the confidence/manual-review overhaul for `generate-vdr-configmap` (modified SKILL.md, archetype-guide.md, example yaml, capture-dataflow SKILL.md, README.md, plus untracked `report_confidence.py` in both trees). The new skill builds on it; commit it first so later tasks start clean.

**Files:**
- Commit (no edits): all currently modified tracked files and the two untracked `report_confidence.py` copies.

**Interfaces:**
- Produces: a clean working tree; the old skill's `scripts/report_confidence.py` exists at `skills/generate-vdr-configmap/scripts/report_confidence.py` (Task 3 adapts a copy of its shape, not the file itself).

- [ ] **Step 1: Verify the mirrors are byte-identical before committing**

Run: `diff -r skills .agents/skills && echo MIRRORS-OK`
Expected: `MIRRORS-OK` and no diff output. If there is a diff, stop and report it — do not "fix" it by guessing which side is right.

- [ ] **Step 2: Commit everything as the foundation**

```bash
git add -A
git commit -m "Emit best-effort assignments with confidence reporting in generate-vdr-configmap"
git status --short
```

Expected: `git status --short` prints nothing.

---

### Task 2: `derive_requirements.py` — derivation math, labels, catalog (TDD)

**Files:**
- Create: `skills/generate-security-requirements-configmap/scripts/derive_requirements.py`
- Create: `tests/loader.py`
- Test: `tests/test_derive_requirements.py`

**Interfaces:**
- Produces (module attributes used by later tasks and tests):
  - `RANK = {"L": 0, "M": 1, "H": 2}`, `LEVELS = ("L", "M", "H")`, `OBJECTIVES = ("c", "i", "a")`
  - `BREAKOUT_CATEGORIES = ("agency-endpoint-delivery", "cross-system-trust-anchor", "shared-csp-infrastructure")`
  - `LABEL_RE` matching `^cr-([lmh])_ir-([lmh])_ar-([lmh])$`
  - `class DerivationError(ValueError)`
  - `normalize_level(value, location) -> str`, `normalize_vector(mapping, location) -> dict`
  - `minimum(left, right) -> dict` (per-objective min)
  - `label_for(vector) -> str`, `vector_for_label(label) -> dict`
  - `catalog_yaml() -> str` (27 entries, `{lens: requirements, cr: X, ir: Y, ar: Z}`)
  - `derive(document) -> dict` with keys `sso`, `aso`, `envelope`, `components`, `labelValuesUsed`
  - CLI: `--emit-catalog` | `--derive <input.json>`; exit 0 ok, 2 on validation error with `error: ...` on stderr.
- Produces: `tests/loader.py` exposing `load_script(stem)` that imports a script from `skills/generate-security-requirements-configmap/scripts/<stem>.py` by path.

- [ ] **Step 1: Write `tests/loader.py`**

```python
"""Load a skill script as a module for unit testing (scripts are not packages)."""
import importlib.util
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "skills" / "generate-security-requirements-configmap" / "scripts"


def load_script(stem):
    path = SCRIPTS / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_derive_requirements.py`:

```python
import itertools
import json
import subprocess
import sys
import unittest
from pathlib import Path

from loader import SCRIPTS, load_script

mod = load_script("derive_requirements")


def doc(sso, aso, components):
    return {"sso": sso, "aso": aso, "components": components}


def vec(c, i, a):
    return {"c": c, "i": i, "a": a}


class MathTests(unittest.TestCase):
    def test_normalize_level_accepts_case_insensitive(self):
        self.assertEqual(mod.normalize_level("m", "x"), "M")
        self.assertEqual(mod.normalize_level(" H ", "x"), "H")

    def test_normalize_level_rejects_garbage(self):
        for bad in ("", "Z", None, 3, "medium?"):
            with self.assertRaises(mod.DerivationError):
                mod.normalize_level(bad, "x")

    def test_normalize_vector_rejects_unknown_objectives(self):
        with self.assertRaises(mod.DerivationError):
            mod.normalize_vector({"c": "M", "i": "M", "a": "M", "q": "H"}, "x")

    def test_minimum_is_per_objective(self):
        self.assertEqual(
            mod.minimum(vec("H", "L", "M"), vec("M", "H", "M")),
            vec("M", "L", "M"),
        )

    def test_label_roundtrip_all_27(self):
        for c, i, a in itertools.product("LMH", repeat=3):
            vector = vec(c, i, a)
            label = mod.label_for(vector)
            self.assertRegex(label, r"^cr-[lmh]_ir-[lmh]_ar-[lmh]$")
            self.assertEqual(mod.vector_for_label(label), vector)

    def test_vector_for_label_rejects_bad_labels(self):
        for bad in ("cr-x_ir-m_ar-l", "cr-m.ir-m.ar-m", "", "cr-m_ir-m", None):
            with self.assertRaises(mod.DerivationError):
                mod.vector_for_label(bad)

    def test_catalog_has_27_unique_entries(self):
        text = mod.catalog_yaml()
        self.assertTrue(text.startswith("archetypes:\n"))
        keys = [line.strip() for line in text.splitlines() if line.strip().startswith('"')]
        self.assertEqual(len(keys), 27)
        self.assertEqual(len(set(keys)), 27)
        self.assertEqual(text.count("lens: requirements"), 27)
        self.assertIn('"cr-l_ir-l_ar-l":', text)
        self.assertIn("{lens: requirements, cr: H, ir: M, ar: L}", text)


class DeriveTests(unittest.TestCase):
    def test_envelope_and_capped_flags(self):
        result = mod.derive(doc(
            vec("M", "M", "M"), vec("M", "M", "L"),
            [{"id": "ns/Deployment/db", "cso": vec("H", "H", "M")}],
        ))
        self.assertEqual(result["envelope"], vec("M", "M", "L"))
        component = result["components"][0]
        self.assertEqual(component["final"], vec("M", "M", "L"))
        self.assertEqual(component["capped"], {"c": True, "i": True, "a": True})
        self.assertEqual(component["securityRequirements"], "cr-m_ir-m_ar-l")
        self.assertEqual(result["labelValuesUsed"], ["cr-m_ir-m_ar-l"])

    def test_component_below_envelope_is_untouched(self):
        result = mod.derive(doc(
            vec("H", "H", "H"), vec("M", "M", "M"),
            [{"id": "ns/Deployment/web", "cso": vec("L", "M", "L")}],
        ))
        component = result["components"][0]
        self.assertEqual(component["final"], vec("L", "M", "L"))
        self.assertEqual(component["capped"], {"c": False, "i": False, "a": False})

    def test_breakout_restores_component_objective(self):
        result = mod.derive(doc(
            vec("M", "M", "M"), vec("M", "M", "M"),
            [{"id": "ns/Deployment/agent-updater", "cso": vec("M", "H", "M"),
              "breakouts": [{"objective": "i",
                             "category": "agency-endpoint-delivery",
                             "justification": "controls the endpoint agent update channel"}]}],
        ))
        component = result["components"][0]
        self.assertEqual(component["final"], vec("M", "H", "M"))
        self.assertEqual(component["capped"], {"c": False, "i": False, "a": False})
        self.assertEqual(component["securityRequirements"], "cr-m_ir-h_ar-m")

    def test_noop_breakout_rejected(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("H", "H", "H"), vec("H", "H", "H"),
                [{"id": "x", "cso": vec("M", "M", "M"),
                  "breakouts": [{"objective": "i",
                                 "category": "cross-system-trust-anchor",
                                 "justification": "y"}]}],
            ))

    def test_unknown_breakout_category_rejected(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("M", "M", "M"), vec("M", "M", "M"),
                [{"id": "x", "cso": vec("H", "M", "M"),
                  "breakouts": [{"objective": "c", "category": "because-i-said-so",
                                 "justification": "y"}]}],
            ))

    def test_duplicate_breakout_objective_rejected(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("M", "M", "M"), vec("M", "M", "M"),
                [{"id": "x", "cso": vec("H", "H", "M"),
                  "breakouts": [
                      {"objective": "c", "category": "cross-system-trust-anchor",
                       "justification": "y"},
                      {"objective": "c", "category": "shared-csp-infrastructure",
                       "justification": "z"}]}],
            ))

    def test_breakout_requires_justification(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("M", "M", "M"), vec("M", "M", "M"),
                [{"id": "x", "cso": vec("H", "M", "M"),
                  "breakouts": [{"objective": "c",
                                 "category": "cross-system-trust-anchor",
                                 "justification": "  "}]}],
            ))

    def test_duplicate_component_ids_rejected(self):
        with self.assertRaises(mod.DerivationError):
            mod.derive(doc(
                vec("M", "M", "M"), vec("M", "M", "M"),
                [{"id": "x", "cso": vec("M", "M", "M")},
                 {"id": "x", "cso": vec("L", "L", "L")}],
            ))


class CliTests(unittest.TestCase):
    SCRIPT = SCRIPTS / "derive_requirements.py"

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(self.SCRIPT), *args],
                              capture_output=True, text=True)

    def test_emit_catalog(self):
        result = self.run_cli("--emit-catalog")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count("lens: requirements"), 27)

    def test_derive_happy_path(self):
        payload = doc(vec("M", "M", "M"), vec("M", "M", "L"),
                      [{"id": "ns/Deployment/db", "cso": vec("H", "H", "M")}])
        path = Path(self.id().replace(".", "_") + ".json")
        path.write_text(json.dumps(payload), encoding="utf-8")
        try:
            result = self.run_cli("--derive", str(path))
        finally:
            path.unlink()
        self.assertEqual(result.returncode, 0)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["components"][0]["securityRequirements"], "cr-m_ir-m_ar-l")

    def test_derive_invalid_exits_2(self):
        path = Path(self.id().replace(".", "_") + ".json")
        path.write_text(json.dumps({"sso": {"c": "Z", "i": "M", "a": "M"},
                                    "aso": {"c": "M", "i": "M", "a": "M"},
                                    "components": []}), encoding="utf-8")
        try:
            result = self.run_cli("--derive", str(path))
        finally:
            path.unlink()
        self.assertEqual(result.returncode, 2)
        self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /Users/matthewvenne/github/trivy-plugin-vdr-skills && python3 -m unittest discover -s tests -v 2>&1 | tail -5`
Expected: FAIL/ERROR (script file does not exist yet, `load_script` raises).

- [ ] **Step 4: Write the implementation**

Create `skills/generate-security-requirements-configmap/scripts/derive_requirements.py`:

```python
#!/usr/bin/env python3
"""Derive final security-requirements vectors and the scoring catalog.

Per objective o in {c, i, a} with L < M < H:
  envelope(o) = min(sso(o), aso(o))
  final(o)    = min(cso(o), envelope(o))
A declared breakout restores final(o) = cso(o) for that objective. A breakout
is valid only when cso(o) exceeds the envelope and its category is one of the
closed list; a no-op breakout is an input error, not a silent pass.

Usage:
  derive_requirements.py --emit-catalog
  derive_requirements.py --derive <input.json>

Derive input document:
{
  "sso": {"c": "M", "i": "M", "a": "M"},
  "aso": {"c": "M", "i": "M", "a": "L"},
  "components": [
    {"id": "namespace/Kind/name",
     "cso": {"c": "H", "i": "H", "a": "M"},
     "breakouts": [{"objective": "i",
                    "category": "agency-endpoint-delivery",
                    "justification": "controls the endpoint agent update channel"}]}
  ]
}

Exit codes: 0 success, 2 validation error (message on stderr).
Requires python3 >= 3.8, standard library only.
"""
import argparse
import json
import re
import sys

RANK = {"L": 0, "M": 1, "H": 2}
LEVELS = ("L", "M", "H")
OBJECTIVES = ("c", "i", "a")
LABEL_RE = re.compile(r"^cr-([lmh])_ir-([lmh])_ar-([lmh])$")
BREAKOUT_CATEGORIES = (
    "agency-endpoint-delivery",
    "cross-system-trust-anchor",
    "shared-csp-infrastructure",
)


class DerivationError(ValueError):
    """Raised when derivation input is invalid."""


def normalize_level(value, location):
    if isinstance(value, str) and value.strip().upper() in RANK:
        return value.strip().upper()
    raise DerivationError(f"{location} must be one of L, M, H")


def normalize_vector(mapping, location):
    if not isinstance(mapping, dict):
        raise DerivationError(f"{location} must be an object with c, i, a")
    unknown = sorted(set(mapping) - set(OBJECTIVES))
    if unknown:
        raise DerivationError(
            f"{location} has unknown objectives: {', '.join(unknown)}"
        )
    return {o: normalize_level(mapping.get(o), f"{location}.{o}") for o in OBJECTIVES}


def minimum(left, right):
    return {
        o: left[o] if RANK[left[o]] <= RANK[right[o]] else right[o]
        for o in OBJECTIVES
    }


def label_for(vector):
    return "cr-{}_ir-{}_ar-{}".format(
        vector["c"].lower(), vector["i"].lower(), vector["a"].lower()
    )


def vector_for_label(label):
    match = LABEL_RE.match(label if isinstance(label, str) else "")
    if not match:
        raise DerivationError(
            f"label {label!r} must match cr-[lmh]_ir-[lmh]_ar-[lmh]"
        )
    return {o: match.group(index + 1).upper() for index, o in enumerate(OBJECTIVES)}


def catalog_yaml():
    lines = ["archetypes:"]
    for c in LEVELS:
        for i in LEVELS:
            for a in LEVELS:
                vector = {"c": c, "i": i, "a": a}
                lines.append(f'  "{label_for(vector)}":')
                lines.append(f"    {{lens: requirements, cr: {c}, ir: {i}, ar: {a}}}")
    return "\n".join(lines) + "\n"


def normalize_breakouts(component, location):
    raw = component.get("breakouts", [])
    if not isinstance(raw, list):
        raise DerivationError(f"{location}.breakouts must be a list")
    breakouts = []
    seen = set()
    for index, entry in enumerate(raw):
        entry_location = f"{location}.breakouts[{index}]"
        if not isinstance(entry, dict):
            raise DerivationError(f"{entry_location} must be an object")
        objective = entry.get("objective")
        if objective not in OBJECTIVES:
            raise DerivationError(f"{entry_location}.objective must be c, i, or a")
        if objective in seen:
            raise DerivationError(f"{entry_location} duplicates objective {objective!r}")
        seen.add(objective)
        category = entry.get("category")
        if category not in BREAKOUT_CATEGORIES:
            raise DerivationError(
                f"{entry_location}.category must be one of: "
                + ", ".join(BREAKOUT_CATEGORIES)
            )
        justification = entry.get("justification")
        if not isinstance(justification, str) or not justification.strip():
            raise DerivationError(
                f"{entry_location}.justification must be a non-empty string"
            )
        breakouts.append({
            "objective": objective,
            "category": category,
            "justification": justification.strip(),
        })
    return breakouts


def derive_component(component, envelope, index):
    location = f"components[{index}]"
    if not isinstance(component, dict):
        raise DerivationError(f"{location} must be an object")
    identity = component.get("id")
    if not isinstance(identity, str) or not identity.strip():
        raise DerivationError(f"{location}.id must be a non-empty string")
    cso = normalize_vector(component.get("cso"), f"{location}.cso")
    breakouts = normalize_breakouts(component, location)
    breakout_objectives = {entry["objective"] for entry in breakouts}
    final = {}
    capped = {}
    for objective in OBJECTIVES:
        if objective in breakout_objectives:
            if RANK[cso[objective]] <= RANK[envelope[objective]]:
                raise DerivationError(
                    f"{location} declares a breakout on {objective!r} but the "
                    f"component objective does not exceed the envelope"
                )
            final[objective] = cso[objective]
        elif RANK[cso[objective]] <= RANK[envelope[objective]]:
            final[objective] = cso[objective]
        else:
            final[objective] = envelope[objective]
        capped[objective] = RANK[final[objective]] < RANK[cso[objective]]
    return {
        "id": identity.strip(),
        "cso": cso,
        "final": final,
        "capped": capped,
        "breakouts": breakouts,
        "securityRequirements": label_for(final),
    }


def derive(document):
    if not isinstance(document, dict):
        raise DerivationError("derive input must be a JSON object")
    sso = normalize_vector(document.get("sso"), "sso")
    aso = normalize_vector(document.get("aso"), "aso")
    envelope = minimum(sso, aso)
    raw_components = document.get("components", [])
    if not isinstance(raw_components, list):
        raise DerivationError("components must be a list")
    components = [
        derive_component(component, envelope, index)
        for index, component in enumerate(raw_components)
    ]
    identities = [component["id"] for component in components]
    if len(identities) != len(set(identities)):
        raise DerivationError("components contains duplicate ids")
    return {
        "sso": sso,
        "aso": aso,
        "envelope": envelope,
        "components": components,
        "labelValuesUsed": sorted({c["securityRequirements"] for c in components}),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Derive security-requirements vectors and the scoring catalog."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--emit-catalog", action="store_true",
                       help="print the 27-entry archetypes catalog YAML")
    group.add_argument("--derive", metavar="INPUT_JSON",
                       help="derive final vectors from an input document")
    args = parser.parse_args()
    if args.emit_catalog:
        sys.stdout.write(catalog_yaml())
        return 0
    try:
        with open(args.derive, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read derive input: {exc}", file=sys.stderr)
        return 2
    try:
        result = derive(document)
    except DerivationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/matthewvenne/github/trivy-plugin-vdr-skills && python3 -m unittest discover -s tests -v 2>&1 | tail -3`
Expected: `OK` with all tests passing.

- [ ] **Step 6: Mirror and verify**

```bash
rsync -a --delete skills/generate-security-requirements-configmap/ .agents/skills/generate-security-requirements-configmap/
diff -r skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap && echo MIRRORS-OK
```

Expected: `MIRRORS-OK`.

- [ ] **Step 7: Commit**

```bash
git add skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap tests/loader.py tests/test_derive_requirements.py
git commit -m "Add security-requirements derivation script with envelope math and catalog"
```

---

### Task 3: `report_confidence.py` — the validation gate (TDD)

**Files:**
- Create: `skills/generate-security-requirements-configmap/scripts/report_confidence.py`
- Test: `tests/test_report_confidence.py`

**Interfaces:**
- Consumes: `tests/loader.py:load_script(stem)` from Task 2.
- Produces CLI: `report_confidence.py <assignment-coverage.json> <security-objectives.json>`; exit 0 valid, 2 invalid with `error: ...` on stderr. Prints three sections in order: `NON-HIGH-CONFIDENCE MANUAL REVIEW (N)`, `CAPPED COMPONENTS (N)`, `BREAKOUTS (N)`, each with `- none` when empty. Never prints `humanReviewCompleted` (it never reads the ConfigMap at all).
- Validates the artifact schemas defined below. These schemas are the contract — Task 5's guide documents the same shapes and Task 6's SKILL.md instructs the agent to produce them.

**`security-objectives.json` schema (validated fields):**

```json
{
  "systemProfile": {
    "product": "non-empty string (generic name is fine)",
    "confirmedDescription": "non-empty string",
    "sso": {"c": {"level": "M", "rationale": "…"}, "i": {…}, "a": {…}},
    "status": "operator-confirmed|agent-inferred",
    "confidence": "high|medium|low",
    "assumptions": ["…"],
    "manualReview": []
  },
  "agencyProfiles": [
    {"agency": "…", "relationship": "definite|target",
     "overlays": [{"name": "…", "statuteGrounded": true}],
     "aso": {"c": {"level": "M", "rationale": "…"}, "i": {…}, "a": {…}},
     "status": "…", "confidence": "…", "assumptions": [], "manualReview": []}
  ],
  "classPrior": {"class": "C", "divergences": [
     {"objective": "c", "estimate": "M", "prior": "H",
      "resolution": "operator-attested", "detail": "…"}]},
  "sso": {"c": "M", "i": "M", "a": "M"},
  "aso": {"c": "M", "i": "M", "a": "L"},
  "envelope": {"c": "M", "i": "M", "a": "L"},
  "ceilingMode": "semi-hard",
  "multiAgencyDetermination": {
    "scope": "cluster|namespace", "clusterDefault": false,
    "multiAgencyNamespaces": ["tenant-*"],
    "justification": "…", "status": "…", "confidence": "…",
    "assumptions": [], "manualReview": []}
}
```

Validation rules: top-level `sso`/`aso`/`envelope` are valid vectors; `envelope == min(sso, aso)` per objective; `ceilingMode == "semi-hard"`; `systemProfile.sso` levels must equal top-level `sso`; when any `relationship == "definite"` profile exists, top-level `aso` must equal the per-objective max over definite profiles' levels; `classPrior.class` in A/B/C/D; each divergence has objective in c/i/a and non-empty `estimate`/`prior`/`resolution`/`detail` with estimate/prior valid levels; `multiAgencyDetermination.scope` in {cluster, namespace}, non-empty `justification`, boolean `clusterDefault`, and when scope is `namespace` a non-empty string list `multiAgencyNamespaces`; `systemProfile`, every agency profile, and `multiAgencyDetermination` all satisfy the status/confidence/manualReview contract and are included in the review report with identities `system-profile/<product>`, `agency-profile/<agency>`, `configuration/multiAgency`.

**`assignment-coverage.json` schema (validated fields):** top-level `context` (non-empty), `inventoryTotal` (non-negative int, == len(assignments)), `assignments` (list, no duplicate namespace/kind/name), `configurationAssumptions` (optional list, same shape as the old skill: `field`, `value`, `evidence`, `assumptions`, `confidence`, `manualReview`), `summary` (not validated). Each assignment:

```json
{"namespace": "…", "kind": "…", "name": "…",
 "componentObjectives": {"c": {"level": "H", "reason": "…"},
                          "i": {"level": "H", "reason": "…"},
                          "a": {"level": "M", "reason": "…"}},
 "vector": "M/M/L",
 "securityRequirements": "cr-m_ir-m_ar-l",
 "capped": {"c": true, "i": true, "a": true},
 "breakouts": [{"objective": "i", "category": "agency-endpoint-delivery",
                "justification": "…"}],
 "resolutionSource": "nameRule",
 "status": "operator-confirmed|agent-inferred",
 "confidence": "high|medium|low",
 "evidence": "…", "assumptions": [], "manualReview": []}
```

Cross-checks per assignment: `securityRequirements` matches the label regex and encodes exactly the `vector`; for each objective, `vector` equals `min(componentObjectives.level, envelope)` unless a breakout on that objective (then it equals the component level, which must exceed the envelope); `capped[o] == (final[o] < cso[o])`; breakout categories from the closed list with non-empty justification, no duplicate objectives; **an assignment with breakouts must not be high confidence**; the high⇒empty / medium-low⇒non-empty manualReview contract holds everywhere.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_report_confidence.py`:

```python
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from loader import SCRIPTS, load_script

mod = load_script("report_confidence")


def level_detail(c, i, a, reason="role evidence"):
    return {"c": {"level": c, "reason": reason},
            "i": {"level": i, "reason": reason},
            "a": {"level": a, "reason": reason}}


def rationale_detail(c, i, a):
    return {"c": {"level": c, "rationale": "data profile"},
            "i": {"level": i, "rationale": "data profile"},
            "a": {"level": a, "rationale": "data profile"}}


def make_objectives():
    return {
        "systemProfile": {
            "product": "generic project management saas",
            "confirmedDescription": "portfolio planning records for one agency",
            "sso": rationale_detail("M", "M", "M"),
            "status": "operator-confirmed", "confidence": "high",
            "assumptions": [], "manualReview": [],
        },
        "agencyProfiles": [{
            "agency": "deploying-agency", "relationship": "definite",
            "overlays": [],
            "aso": rationale_detail("M", "M", "L"),
            "status": "operator-confirmed", "confidence": "high",
            "assumptions": [], "manualReview": [],
        }],
        "classPrior": {"class": "C", "divergences": []},
        "sso": {"c": "M", "i": "M", "a": "M"},
        "aso": {"c": "M", "i": "M", "a": "L"},
        "envelope": {"c": "M", "i": "M", "a": "L"},
        "ceilingMode": "semi-hard",
        "multiAgencyDetermination": {
            "scope": "cluster", "clusterDefault": False,
            "justification": "single tenant cluster",
            "status": "operator-confirmed", "confidence": "high",
            "assumptions": [], "manualReview": [],
        },
    }


def make_coverage():
    return {
        "context": "test-context",
        "inventoryTotal": 2,
        "assignments": [
            {"namespace": "app", "kind": "Deployment", "name": "db",
             "componentObjectives": level_detail("H", "H", "M"),
             "vector": "M/M/L", "securityRequirements": "cr-m_ir-m_ar-l",
             "capped": {"c": True, "i": True, "a": True},
             "resolutionSource": "nameRule", "status": "agent-inferred",
             "confidence": "medium", "evidence": "statefulset with pvc",
             "assumptions": ["system of record"],
             "manualReview": ["confirm the record store role"]},
            {"namespace": "app", "kind": "Deployment", "name": "agent-updater",
             "componentObjectives": level_detail("M", "H", "L"),
             "vector": "M/H/L", "securityRequirements": "cr-m_ir-h_ar-l",
             "capped": {"c": False, "i": False, "a": False},
             "breakouts": [{"objective": "i",
                            "category": "agency-endpoint-delivery",
                            "justification": "ships agents to agency devices"}],
             "resolutionSource": "nameRule", "status": "agent-inferred",
             "confidence": "medium", "evidence": "update channel service",
             "assumptions": [],
             "manualReview": ["verify endpoint update path"]},
        ],
        "configurationAssumptions": [],
        "summary": {},
    }


class GateTests(unittest.TestCase):
    def check(self, coverage, objectives):
        with tempfile.TemporaryDirectory() as tmp:
            cov = Path(tmp) / "coverage.json"
            obj = Path(tmp) / "objectives.json"
            cov.write_text(json.dumps(coverage), encoding="utf-8")
            obj.write_text(json.dumps(objectives), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPTS / "report_confidence.py"),
                 str(cov), str(obj)],
                capture_output=True, text=True)

    def test_happy_path_prints_sections(self):
        result = self.check(make_coverage(), make_objectives())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NON-HIGH-CONFIDENCE MANUAL REVIEW (2)", result.stdout)
        self.assertIn("CAPPED COMPONENTS (1)", result.stdout)
        self.assertIn("CR H->M", result.stdout)
        self.assertIn("BREAKOUTS (1)", result.stdout)
        self.assertIn("agency-endpoint-delivery", result.stdout)
        self.assertNotIn("humanReviewCompleted", result.stdout)

    def test_envelope_must_be_min(self):
        objectives = make_objectives()
        objectives["envelope"] = {"c": "H", "i": "M", "a": "L"}
        result = self.check(make_coverage(), objectives)
        self.assertEqual(result.returncode, 2)
        self.assertIn("envelope", result.stderr)

    def test_final_must_match_envelope_math(self):
        coverage = make_coverage()
        coverage["assignments"][0]["vector"] = "H/M/L"
        coverage["assignments"][0]["securityRequirements"] = "cr-h_ir-m_ar-l"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_label_must_encode_vector(self):
        coverage = make_coverage()
        coverage["assignments"][0]["securityRequirements"] = "cr-l_ir-m_ar-l"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_capped_flags_must_be_accurate(self):
        coverage = make_coverage()
        coverage["assignments"][0]["capped"]["c"] = False
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_breakout_cannot_be_high_confidence(self):
        coverage = make_coverage()
        coverage["assignments"][1]["confidence"] = "high"
        coverage["assignments"][1]["manualReview"] = []
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_noop_breakout_rejected(self):
        coverage = make_coverage()
        record = coverage["assignments"][1]
        record["componentObjectives"] = level_detail("M", "M", "L")
        record["vector"] = "M/M/L"
        record["securityRequirements"] = "cr-m_ir-m_ar-l"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_unknown_breakout_category_rejected(self):
        coverage = make_coverage()
        coverage["assignments"][1]["breakouts"][0]["category"] = "vibes"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_inventory_equation_enforced(self):
        coverage = make_coverage()
        coverage["inventoryTotal"] = 3
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_duplicate_assignments_rejected(self):
        coverage = make_coverage()
        coverage["assignments"].append(copy.deepcopy(coverage["assignments"][0]))
        coverage["inventoryTotal"] = 3
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_high_confidence_requires_empty_review(self):
        coverage = make_coverage()
        coverage["assignments"][0]["confidence"] = "high"
        result = self.check(coverage, make_objectives())
        self.assertEqual(result.returncode, 2)

    def test_definite_agency_max_sets_aso(self):
        objectives = make_objectives()
        objectives["agencyProfiles"].append({
            "agency": "second-agency", "relationship": "definite",
            "overlays": [],
            "aso": rationale_detail("H", "M", "L"),
            "status": "agent-inferred", "confidence": "medium",
            "assumptions": [], "manualReview": ["confirm agency data profile"],
        })
        result = self.check(make_coverage(), objectives)
        self.assertEqual(result.returncode, 2)
        self.assertIn("aso", result.stderr)

    def test_namespace_scope_requires_namespaces(self):
        objectives = make_objectives()
        objectives["multiAgencyDetermination"]["scope"] = "namespace"
        result = self.check(make_coverage(), objectives)
        self.assertEqual(result.returncode, 2)

    def test_ceiling_mode_enforced(self):
        objectives = make_objectives()
        objectives["ceilingMode"] = "hard"
        result = self.check(make_coverage(), objectives)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_report_confidence -v 2>&1 | tail -3` (from repo root; if module discovery complains, use `cd tests && python3 -m unittest test_report_confidence -v`)
Expected: ERROR — `report_confidence.py` does not exist in the new skill's scripts directory.

- [ ] **Step 3: Write the implementation**

Create `skills/generate-security-requirements-configmap/scripts/report_confidence.py`. Reuse the old gate's helper style (`skills/generate-vdr-configmap/scripts/report_confidence.py`) but implement this full content:

```python
#!/usr/bin/env python3
"""Validate security-requirements coverage artifacts and print the review report.

Usage: report_confidence.py <assignment-coverage.json> <security-objectives.json>

Checks the confidence contract, the envelope math
(final = min(component objective, envelope) unless a recorded breakout
applies), breakout legitimacy, capped-flag accuracy, and label/vector
consistency. Prints every medium/low-confidence decision, every capped
component, and every breakout. Exit 0 when valid, 2 when invalid.

This gate never reads the generated ConfigMap and never prints the
humanReviewCompleted attestation marker.
"""

import argparse
import json
import re
import sys

CONFIDENCE = {"high", "medium", "low"}
STATUS = {"operator-confirmed", "agent-inferred"}
RANK = {"L": 0, "M": 1, "H": 2}
OBJECTIVES = ("c", "i", "a")
OBJECTIVE_NAMES = {"c": "CR", "i": "IR", "a": "AR"}
LABEL_RE = re.compile(r"^cr-([lmh])_ir-([lmh])_ar-([lmh])$")
BREAKOUT_CATEGORIES = {
    "agency-endpoint-delivery",
    "cross-system-trust-anchor",
    "shared-csp-infrastructure",
}
CLASSES = {"A", "B", "C", "D"}
SCOPES = {"cluster", "namespace"}
RELATIONSHIPS = {"definite", "target"}


class CoverageError(ValueError):
    """Raised when an artifact document is incomplete or inconsistent."""


def require_string(record, field, location):
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CoverageError(f"{location}.{field} must be a non-empty string")
    return value.strip()


def require_string_list(record, field, location):
    value = record.get(field)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise CoverageError(f"{location}.{field} must be a list of non-empty strings")
    return [item.strip() for item in value]


def require_confidence(record, location):
    confidence = require_string(record, "confidence", location).lower()
    if confidence not in CONFIDENCE:
        raise CoverageError(f"{location}.confidence must be high, medium, or low")
    reviews = require_string_list(record, "manualReview", location)
    if confidence == "high" and reviews:
        raise CoverageError(
            f"{location}.manualReview must be empty when confidence is high"
        )
    if confidence != "high" and not reviews:
        raise CoverageError(
            f"{location}.manualReview needs at least one item when confidence "
            f"is {confidence}"
        )
    return confidence, reviews


def require_status(record, location):
    status = require_string(record, "status", location)
    if status not in STATUS:
        raise CoverageError(
            f"{location}.status must be operator-confirmed or agent-inferred"
        )
    return status


def require_level(value, location):
    if isinstance(value, str) and value.strip().upper() in RANK:
        return value.strip().upper()
    raise CoverageError(f"{location} must be H, M, or L")


def require_vector(mapping, location):
    if not isinstance(mapping, dict):
        raise CoverageError(f"{location} must be an object with c, i, a")
    return {o: require_level(mapping.get(o), f"{location}.{o}") for o in OBJECTIVES}


def require_objective_details(mapping, location, text_field):
    if not isinstance(mapping, dict):
        raise CoverageError(f"{location} must be an object with c, i, a")
    details = {}
    for objective in OBJECTIVES:
        entry = mapping.get(objective)
        if not isinstance(entry, dict):
            raise CoverageError(f"{location}.{objective} must be an object")
        details[objective] = {
            "level": require_level(entry.get("level"), f"{location}.{objective}.level"),
            text_field: require_string(entry, text_field, f"{location}.{objective}"),
        }
    return details


def vector_text(value, location):
    if isinstance(value, str) and value.strip():
        result = value.strip().upper()
        if len(result) == 5 and result[1] == result[3] == "/":
            if all(result[index] in RANK for index in (0, 2, 4)):
                return result
        raise CoverageError(f"{location}.vector string must look like H/M/L")
    if isinstance(value, dict):
        try:
            values = [str(value[key]).upper() for key in ("cr", "ir", "ar")]
        except KeyError as exc:
            raise CoverageError(
                f"{location}.vector object must contain cr, ir, and ar"
            ) from exc
        if any(item not in RANK for item in values):
            raise CoverageError(f"{location}.vector values must be H, M, or L")
        return "/".join(values)
    raise CoverageError(f"{location}.vector must be an H/M/L string or cr/ir/ar object")


def vector_from_text(text):
    return {"c": text[0], "i": text[2], "a": text[4]}


def normalize_breakouts(record, location):
    raw = record.get("breakouts", [])
    if not isinstance(raw, list):
        raise CoverageError(f"{location}.breakouts must be a list")
    breakouts = []
    seen = set()
    for index, entry in enumerate(raw):
        entry_location = f"{location}.breakouts[{index}]"
        if not isinstance(entry, dict):
            raise CoverageError(f"{entry_location} must be an object")
        objective = entry.get("objective")
        if objective not in OBJECTIVES:
            raise CoverageError(f"{entry_location}.objective must be c, i, or a")
        if objective in seen:
            raise CoverageError(f"{entry_location} duplicates objective {objective!r}")
        seen.add(objective)
        category = entry.get("category")
        if category not in BREAKOUT_CATEGORIES:
            raise CoverageError(
                f"{entry_location}.category must be one of: "
                + ", ".join(sorted(BREAKOUT_CATEGORIES))
            )
        justification = require_string(entry, "justification", entry_location)
        breakouts.append({
            "objective": objective,
            "category": category,
            "justification": justification,
        })
    return breakouts


def normalize_assignment(record, index, envelope):
    location = f"assignments[{index}]"
    if not isinstance(record, dict):
        raise CoverageError(f"{location} must be an object")
    namespace = require_string(record, "namespace", location)
    kind = require_string(record, "kind", location)
    name = require_string(record, "name", location)
    details = require_objective_details(
        record.get("componentObjectives"), f"{location}.componentObjectives", "reason"
    )
    cso = {objective: details[objective]["level"] for objective in OBJECTIVES}
    final_text = vector_text(record.get("vector"), location)
    final = vector_from_text(final_text)
    label = require_string(record, "securityRequirements", location)
    match = LABEL_RE.match(label)
    if not match:
        raise CoverageError(
            f"{location}.securityRequirements must match cr-[lmh]_ir-[lmh]_ar-[lmh]"
        )
    encoded = {
        objective: match.group(position + 1).upper()
        for position, objective in enumerate(OBJECTIVES)
    }
    if encoded != final:
        raise CoverageError(
            f"{location}.securityRequirements does not encode vector {final_text}"
        )
    breakouts = normalize_breakouts(record, location)
    breakout_objectives = {entry["objective"] for entry in breakouts}
    capped = record.get("capped")
    if not isinstance(capped, dict) or any(
        not isinstance(capped.get(objective), bool) for objective in OBJECTIVES
    ):
        raise CoverageError(f"{location}.capped must map c, i, a to booleans")
    require_string(record, "resolutionSource", location)
    status = require_status(record, location)
    evidence = require_string(record, "evidence", location)
    assumptions = require_string_list(record, "assumptions", location)
    confidence, reviews = require_confidence(record, location)
    if breakouts and confidence == "high":
        raise CoverageError(
            f"{location} declares a breakout and must not be high confidence"
        )
    for objective in OBJECTIVES:
        if objective in breakout_objectives:
            if RANK[cso[objective]] <= RANK[envelope[objective]]:
                raise CoverageError(
                    f"{location} declares a breakout on {objective!r} but the "
                    f"component objective does not exceed the envelope"
                )
            expected = cso[objective]
        elif RANK[cso[objective]] <= RANK[envelope[objective]]:
            expected = cso[objective]
        else:
            expected = envelope[objective]
        if final[objective] != expected:
            raise CoverageError(
                f"{location}.vector {OBJECTIVE_NAMES[objective]} must be "
                f"{expected}: min(component objective, envelope) unless a "
                f"recorded breakout applies"
            )
        expected_capped = RANK[final[objective]] < RANK[cso[objective]]
        if capped[objective] != expected_capped:
            raise CoverageError(
                f"{location}.capped.{objective} must be "
                f"{str(expected_capped).lower()}"
            )
    caps = [
        f"{OBJECTIVE_NAMES[objective]} {cso[objective]}->{final[objective]}"
        for objective in OBJECTIVES
        if capped[objective]
    ]
    return {
        "identity": f"{namespace}/{kind}/{name}",
        "selected": f"{label} -> {final_text}",
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
        "assumptions": assumptions,
        "reviews": reviews,
        "caps": caps,
        "breakouts": breakouts,
        "key": (namespace, kind, name),
    }


def normalize_configuration(record, index):
    location = f"configurationAssumptions[{index}]"
    if not isinstance(record, dict):
        raise CoverageError(f"{location} must be an object")
    field = require_string(record, "field", location)
    if "value" not in record:
        raise CoverageError(f"{location}.value is required")
    value = json.dumps(record["value"], sort_keys=True)
    evidence = require_string(record, "evidence", location)
    assumptions = require_string_list(record, "assumptions", location)
    confidence, reviews = require_confidence(record, location)
    return {
        "identity": f"configuration/{field}",
        "selected": value,
        "status": "agent-inferred",
        "confidence": confidence,
        "evidence": evidence,
        "assumptions": assumptions,
        "reviews": reviews,
    }


def profile_record(record, identity, selected, location):
    status = require_status(record, location)
    confidence, reviews = require_confidence(record, location)
    assumptions = require_string_list(record, "assumptions", location)
    return {
        "identity": identity,
        "selected": selected,
        "status": status,
        "confidence": confidence,
        "evidence": require_string(record, "confirmedDescription", location)
        if "confirmedDescription" in record
        else require_string(record, "justification", location)
        if "justification" in record
        else "recorded profile",
        "assumptions": assumptions,
        "reviews": reviews,
    }


def load_objectives(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageError(f"cannot read objectives JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CoverageError("objectives document must be a JSON object")

    sso = require_vector(document.get("sso"), "objectives.sso")
    aso = require_vector(document.get("aso"), "objectives.aso")
    envelope = require_vector(document.get("envelope"), "objectives.envelope")
    for objective in OBJECTIVES:
        expected = (
            sso[objective]
            if RANK[sso[objective]] <= RANK[aso[objective]]
            else aso[objective]
        )
        if envelope[objective] != expected:
            raise CoverageError(
                f"objectives.envelope.{objective} must be min(sso, aso) = {expected}"
            )
    if document.get("ceilingMode") != "semi-hard":
        raise CoverageError('objectives.ceilingMode must be "semi-hard"')

    records = []

    system_profile = document.get("systemProfile")
    if not isinstance(system_profile, dict):
        raise CoverageError("objectives.systemProfile must be an object")
    product = require_string(system_profile, "product", "objectives.systemProfile")
    require_string(system_profile, "confirmedDescription", "objectives.systemProfile")
    system_details = require_objective_details(
        system_profile.get("sso"), "objectives.systemProfile.sso", "rationale"
    )
    for objective in OBJECTIVES:
        if system_details[objective]["level"] != sso[objective]:
            raise CoverageError(
                f"objectives.systemProfile.sso.{objective} must match "
                f"objectives.sso ({sso[objective]})"
            )
    records.append(profile_record(
        system_profile, f"system-profile/{product}",
        "SSO " + "/".join(sso[o] for o in OBJECTIVES),
        "objectives.systemProfile",
    ))

    raw_profiles = document.get("agencyProfiles", [])
    if not isinstance(raw_profiles, list):
        raise CoverageError("objectives.agencyProfiles must be a list")
    definite_levels = {objective: [] for objective in OBJECTIVES}
    for index, profile in enumerate(raw_profiles):
        location = f"objectives.agencyProfiles[{index}]"
        if not isinstance(profile, dict):
            raise CoverageError(f"{location} must be an object")
        agency = require_string(profile, "agency", location)
        relationship = require_string(profile, "relationship", location)
        if relationship not in RELATIONSHIPS:
            raise CoverageError(f"{location}.relationship must be definite or target")
        details = require_objective_details(
            profile.get("aso"), f"{location}.aso", "rationale"
        )
        if relationship == "definite":
            for objective in OBJECTIVES:
                definite_levels[objective].append(details[objective]["level"])
        overlays = profile.get("overlays", [])
        if not isinstance(overlays, list):
            raise CoverageError(f"{location}.overlays must be a list")
        for overlay_index, overlay in enumerate(overlays):
            overlay_location = f"{location}.overlays[{overlay_index}]"
            if not isinstance(overlay, dict):
                raise CoverageError(f"{overlay_location} must be an object")
            require_string(overlay, "name", overlay_location)
            if not isinstance(overlay.get("statuteGrounded"), bool):
                raise CoverageError(
                    f"{overlay_location}.statuteGrounded must be a boolean"
                )
        profile.setdefault("justification", "recorded agency profile")
        records.append(profile_record(
            profile, f"agency-profile/{agency}",
            "ASO " + "/".join(details[o]["level"] for o in OBJECTIVES)
            + f" ({relationship})",
            location,
        ))
    if any(definite_levels[objective] for objective in OBJECTIVES):
        for objective in OBJECTIVES:
            expected = max(definite_levels[objective], key=lambda level: RANK[level])
            if aso[objective] != expected:
                raise CoverageError(
                    f"objectives.aso.{objective} must equal the per-objective max "
                    f"over definite agency profiles ({expected})"
                )

    class_prior = document.get("classPrior")
    if not isinstance(class_prior, dict):
        raise CoverageError("objectives.classPrior must be an object")
    prior_class = require_string(class_prior, "class", "objectives.classPrior").upper()
    if prior_class not in CLASSES:
        raise CoverageError("objectives.classPrior.class must be A, B, C, or D")
    divergences = class_prior.get("divergences", [])
    if not isinstance(divergences, list):
        raise CoverageError("objectives.classPrior.divergences must be a list")
    for index, divergence in enumerate(divergences):
        location = f"objectives.classPrior.divergences[{index}]"
        if not isinstance(divergence, dict):
            raise CoverageError(f"{location} must be an object")
        if divergence.get("objective") not in OBJECTIVES:
            raise CoverageError(f"{location}.objective must be c, i, or a")
        require_level(divergence.get("estimate"), f"{location}.estimate")
        require_level(divergence.get("prior"), f"{location}.prior")
        require_string(divergence, "resolution", location)
        require_string(divergence, "detail", location)

    determination = document.get("multiAgencyDetermination")
    if not isinstance(determination, dict):
        raise CoverageError("objectives.multiAgencyDetermination must be an object")
    scope = require_string(determination, "scope", "objectives.multiAgencyDetermination")
    if scope not in SCOPES:
        raise CoverageError(
            "objectives.multiAgencyDetermination.scope must be cluster or namespace"
        )
    if not isinstance(determination.get("clusterDefault"), bool):
        raise CoverageError(
            "objectives.multiAgencyDetermination.clusterDefault must be a boolean"
        )
    require_string(determination, "justification", "objectives.multiAgencyDetermination")
    if scope == "namespace":
        namespaces = determination.get("multiAgencyNamespaces")
        if (
            not isinstance(namespaces, list)
            or not namespaces
            or any(not isinstance(item, str) or not item.strip() for item in namespaces)
        ):
            raise CoverageError(
                "objectives.multiAgencyDetermination.multiAgencyNamespaces must "
                "be a non-empty list of non-empty strings when scope is namespace"
            )
    records.append(profile_record(
        determination, "configuration/multiAgency",
        f"scope={scope} clusterDefault={determination['clusterDefault']}",
        "objectives.multiAgencyDetermination",
    ))

    return envelope, records


def load_coverage(path, envelope):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise CoverageError(f"cannot read coverage JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CoverageError("coverage document must be a JSON object")

    require_string(document, "context", "coverage")
    inventory_total = document.get("inventoryTotal")
    if not isinstance(inventory_total, int) or inventory_total < 0:
        raise CoverageError("inventoryTotal must be a non-negative integer")

    raw_assignments = document.get("assignments")
    if not isinstance(raw_assignments, list):
        raise CoverageError("assignments must be a list")
    assignments = [
        normalize_assignment(record, index, envelope)
        for index, record in enumerate(raw_assignments)
    ]
    if len(assignments) != inventory_total:
        raise CoverageError(
            f"inventoryTotal is {inventory_total}, but assignments has "
            f"{len(assignments)} entries"
        )
    keys = [record["key"] for record in assignments]
    if len(keys) != len(set(keys)):
        raise CoverageError("assignments contains duplicate namespace/kind/name entries")

    raw_configuration = document.get("configurationAssumptions", [])
    if not isinstance(raw_configuration, list):
        raise CoverageError("configurationAssumptions must be a list")
    configuration = [
        normalize_configuration(record, index)
        for index, record in enumerate(raw_configuration)
    ]
    return assignments, configuration


def print_review(records):
    review = [record for record in records if record["confidence"] != "high"]
    order = {"low": 0, "medium": 1}
    review.sort(key=lambda record: (order[record["confidence"]], record["identity"]))
    print(f"NON-HIGH-CONFIDENCE MANUAL REVIEW ({len(review)})")
    if not review:
        print("- none")
        return
    for record in review:
        print(
            f"- [{record['confidence'].upper()}] {record['identity']} "
            f"({record['status']})"
        )
        print(f"  Selected: {record['selected']}")
        print(f"  Evidence: {record['evidence']}")
        if record["assumptions"]:
            print(f"  Assumptions: {'; '.join(record['assumptions'])}")
        for item in record["reviews"]:
            print(f"  Review: {item}")


def print_caps(assignments):
    capped = [record for record in assignments if record["caps"]]
    print(f"CAPPED COMPONENTS ({len(capped)})")
    if not capped:
        print("- none")
        return
    for record in capped:
        print(f"- {record['identity']}: {', '.join(record['caps'])}")


def print_breakouts(assignments):
    with_breakouts = [record for record in assignments if record["breakouts"]]
    total = sum(len(record["breakouts"]) for record in with_breakouts)
    print(f"BREAKOUTS ({total})")
    if not with_breakouts:
        print("- none")
        return
    for record in with_breakouts:
        for entry in record["breakouts"]:
            print(
                f"- {record['identity']} [{OBJECTIVE_NAMES[entry['objective']]}] "
                f"{entry['category']}: {entry['justification']}"
            )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Validate security-requirements coverage artifacts and print the "
            "manual-review, capped-component, and breakout report."
        )
    )
    parser.add_argument("coverage", help="path to assignment-coverage.json")
    parser.add_argument("objectives", help="path to security-objectives.json")
    args = parser.parse_args()
    try:
        envelope, objective_records = load_objectives(args.objectives)
        assignments, configuration = load_coverage(args.coverage, envelope)
        print_review(assignments + configuration + objective_records)
        print_caps(assignments)
        print_breakouts(assignments)
    except CoverageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v 2>&1 | tail -3`
Expected: `OK`.

- [ ] **Step 5: Mirror, verify, commit**

```bash
rsync -a --delete skills/generate-security-requirements-configmap/ .agents/skills/generate-security-requirements-configmap/
diff -r skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap && echo MIRRORS-OK
git add skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap tests/test_report_confidence.py
git commit -m "Add coverage validation gate for security-requirements artifacts"
```

---

### Task 4: `list_workloads.py` — adapted inventory collector (TDD)

**Files:**
- Create: `skills/generate-security-requirements-configmap/scripts/list_workloads.py` (adapted copy of `skills/generate-vdr-configmap/scripts/list_workloads.py`)
- Test: `tests/test_list_workloads.py`

**Interfaces:**
- Consumes: the old collector at `skills/generate-vdr-configmap/scripts/list_workloads.py` as the base (copy it, then edit).
- Produces: same CLI (`--context <name>` required, optional `-n <ns>`), same evidence model, but workload records carry `securityRequirements` and `legacyArchetype` instead of `archetype`, and the summary uses the new counters below. The v0.1 deprecated alias fields are dropped in this copy.

- [ ] **Step 1: Write the failing test**

Create `tests/test_list_workloads.py`:

```python
import unittest

from loader import load_script

mod = load_script("list_workloads")


def deployment_item(labels=None, template_labels=None):
    return {
        "kind": "Deployment",
        "metadata": {"namespace": "app", "name": "web", "labels": labels or {}},
        "spec": {"template": {
            "metadata": {"labels": template_labels or {}},
            "spec": {"containers": [{"name": "web", "image": "registry.example/web:1"}]},
        }},
    }


class LabelTests(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(mod.SECURITY_REQUIREMENTS_LABEL,
                         "vdr.fedramp.io/security-requirements")
        self.assertEqual(mod.LEGACY_ARCHETYPE_LABEL,
                         "vdr.fedramp.io/asset-archetype")

    def test_entry_reports_both_labels(self):
        item = deployment_item(labels={
            "vdr.fedramp.io/security-requirements": "cr-m_ir-m_ar-l",
            "vdr.fedramp.io/asset-archetype": "service-content.bounded-processing.bounded-service",
        })
        entry = mod.workload_entry("Deployment", item)
        self.assertEqual(entry["securityRequirements"], "cr-m_ir-m_ar-l")
        self.assertEqual(entry["legacyArchetype"],
                         "service-content.bounded-processing.bounded-service")
        self.assertNotIn("archetype", entry)
        self.assertNotIn("cloudManagedNamespace", entry)

    def test_pod_template_labels_win(self):
        item = deployment_item(
            labels={"vdr.fedramp.io/security-requirements": "cr-l_ir-l_ar-l"},
            template_labels={"vdr.fedramp.io/security-requirements": "cr-h_ir-h_ar-h"},
        )
        entry = mod.workload_entry("Deployment", item)
        self.assertEqual(entry["securityRequirements"], "cr-h_ir-h_ar-h")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest discover -s tests -v 2>&1 | tail -3`
Expected: ERROR — `list_workloads.py` missing from the new skill.

- [ ] **Step 3: Copy and adapt the collector**

```bash
cp skills/generate-vdr-configmap/scripts/list_workloads.py \
   skills/generate-security-requirements-configmap/scripts/list_workloads.py
```

Then apply these exact edits to the new copy (leave the old skill's file untouched):

1. Replace the module docstring (the whole triple-quoted block at the top) with:

```python
"""Read-only inventory of cluster workloads for vdr-fedramp ConfigMap generation.

Usage: list_workloads.py --context <reviewed-context>            (all namespaces)
       list_workloads.py --context <reviewed-context> -n <ns>    (single namespace)
Requires: kubectl (authenticated), python3 (>=3.8, stdlib only).

Emits one JSON document on stdout:
  - namespaces: name, managedNamespaceHint, vdr.fedramp.io/* labels
  - workloads: namespace, kind, name, effective
    vdr.fedramp.io/security-requirements label, any stale legacy
    vdr.fedramp.io/asset-archetype label, images, service account, non-secret
    privilege/data-reference evidence, and a managedNamespaceHint (namespace
    alone does not decide ownership)
  - summary counts (total / security-requirements label presence / stale
    legacy labels / managed-namespace hint)

Only `kubectl get` and `kubectl config` are executed — never
exec/apply/label/patch/delete.
"""
```

2. Replace the constants block:

```python
VDR_LABEL_PREFIX = "vdr.fedramp.io/"
ARCHETYPE_LABEL = "vdr.fedramp.io/asset-archetype"
```

with:

```python
VDR_LABEL_PREFIX = "vdr.fedramp.io/"
SECURITY_REQUIREMENTS_LABEL = "vdr.fedramp.io/security-requirements"
# Legacy vocabulary: inert once labelKeys renames the archetype key, but
# reported so the operator can clean up stale labels.
LEGACY_ARCHETYPE_LABEL = "vdr.fedramp.io/asset-archetype"
```

3. In `workload_entry`, replace:

```python
        "archetype": labels.get(ARCHETYPE_LABEL),
```

with:

```python
        "securityRequirements": labels.get(SECURITY_REQUIREMENTS_LABEL),
        "legacyArchetype": labels.get(LEGACY_ARCHETYPE_LABEL),
```

and delete these two lines from the same return dict (dropped v0.1 alias):

```python
        # Retained for consumers of the v0.1 inventory schema. Treat as a hint.
        "cloudManagedNamespace": managed_hint,
```

4. In `collect_namespaces`, delete the alias lines:

```python
            # Retained for consumers of the v0.1 inventory schema.
            "cloudManaged": is_cloud_managed(name),
```

5. Replace the whole summary block in `main()` (from `labeled = sum(...)` through the end of the `"summary": {...}` dict) with:

```python
    sr_labeled = sum(
        1 for w in workloads if SECURITY_REQUIREMENTS_LABEL in w["vdrLabels"]
    )
    sr_object = sum(
        1 for w in workloads
        if SECURITY_REQUIREMENTS_LABEL in w["workloadObjectVdrLabels"]
    )
    sr_template = sum(
        1 for w in workloads
        if SECURITY_REQUIREMENTS_LABEL in w["podTemplateVdrLabels"]
    )
    legacy_labeled = sum(
        1 for w in workloads if LEGACY_ARCHETYPE_LABEL in w["vdrLabels"]
    )
    managed = sum(1 for w in workloads if w["managedNamespaceHint"])
    doc = {
        "context": context,
        "scope": scope,
        "namespaces": namespaces,
        "workloads": workloads,
        "summary": {
            "workloads": len(workloads),
            "withEffectiveSecurityRequirementsLabel": sr_labeled,
            "withoutEffectiveSecurityRequirementsLabel": len(workloads) - sr_labeled,
            "withWorkloadObjectSecurityRequirementsLabel": sr_object,
            "withPodTemplateSecurityRequirementsLabel": sr_template,
            # Stale once labelKeys renames the archetype key; report for cleanup.
            "withLegacyArchetypeLabel": legacy_labeled,
            "inManagedNamespacePatterns": managed,
        },
    }
```

- [ ] **Step 4: Run tests and a compile/help smoke check**

```bash
python3 -m unittest discover -s tests -v 2>&1 | tail -3
python3 -m py_compile skills/generate-security-requirements-configmap/scripts/list_workloads.py
python3 skills/generate-security-requirements-configmap/scripts/list_workloads.py --help >/dev/null; echo "help-exit=$?"
```

Expected: `OK`; no compile output; `help-exit=0`.

- [ ] **Step 5: Mirror, verify, commit**

```bash
rsync -a --delete skills/generate-security-requirements-configmap/ .agents/skills/generate-security-requirements-configmap/
diff -r skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap && echo MIRRORS-OK
git add skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap tests/test_list_workloads.py
git commit -m "Add workload inventory collector for the security-requirements skill"
```

---

### Task 5: `references/security-objectives-guide.md`

**Files:**
- Create: `skills/generate-security-requirements-configmap/references/security-objectives-guide.md`

**Interfaces:**
- Consumes: script CLIs from Tasks 2-4 (`derive_requirements.py --emit-catalog|--derive`, `report_confidence.py <coverage> <objectives>`); artifact schemas from Task 3.
- Produces: the reference document Task 6's SKILL.md points to with "Read `references/security-objectives-guide.md` completely before the wizard."

- [ ] **Step 1: Write the guide with this exact content**

```markdown
# Security objectives derivation guide

Turn operator answers, product/agency research, and read-only cluster evidence
into an auditable per-component Security Requirements vector. No real product,
vendor, or agency names appear in this guide or in any example artifact; use
generic system-type language when writing reusable content.

## Contents

1. [Model](#model)
2. [Combination math](#combination-math)
3. [Breakout categories](#breakout-categories)
4. [Calibration rules](#calibration-rules)
5. [System-type starting profiles](#system-type-starting-profiles)
6. [Wizard question bank](#wizard-question-bank)
7. [Class-vs-data divergence protocol](#class-vs-data-divergence-protocol)
8. [Multi-agency determination](#multi-agency-determination)
9. [Component-objective methodology](#component-objective-methodology)
10. [Confidence and review](#confidence-and-review)
11. [Artifact schemas](#artifact-schemas)
12. [Runtime mechanics](#runtime-mechanics)

## Model

Three per-objective vectors, each `{C, I, A}` over `{L, M, H}` with L < M < H:

- **System Security Objectives (SSO):** what the product holds and does by
  design — from consented web research the operator confirms, the data-type
  checklist, ingestion/contamination paths, and the agency-device footprint.
- **Agency Security Objectives (ASO):** a per-objective estimate of the data
  the deploying agency would actually place in this system. Never the agency's
  overall FIPS 199 high-water mark; always objective-level. Grounded in agency
  research, statutory/contractual overlays, and any known objective-level
  categorization from solicitations, privacy impact assessments, or the agency
  authorization package.
- **Component Security Objectives (CSO):** the per-workload role evaluation
  from structural evidence and focused impact questions (section 9).

CR/IR/AR carry the standard CVSS environmental weights (H=1.5, M=1.0, L=0.5)
at runtime; this guide only decides which letter each component gets.

## Combination math

Per objective `o` in `{C, I, A}`:

```text
envelope(o) = min(SSO(o), ASO(o))    # agency caps system; a higher agency value never raises it
final(o)    = min(CSO(o), envelope(o))
```

The envelope is only ever a cap, never a floor. Contamination evidence raises
SSO during the wizard; role evidence raises CSO; the formula itself raises
nothing. Record the raw CSO and the final vector for every component, with a
per-objective `capped` flag, so every cap is visible in review.

Compute with `scripts/derive_requirements.py --derive <input.json>` — never by
hand. The script also rejects malformed breakouts.

Worked example (generic): a project-management SaaS deployed for one agency.
SSO `{M, M, M}` (durable planning records; permanent loss is serious), ASO
`{M, M, L}` (agency places moderate planning data; loss of this instance is
limited for them) → envelope `{M, M, L}`. A system-of-record database with CSO
`{H, H, M}` finalizes at `{M, M, L}` — all three capped, all three recorded. An
update service that ships endpoint agents to agency devices with CSO
`{M, H, L}` takes an integrity breakout and finalizes at `{M, H, L}`.

## Breakout categories

A component may exceed the envelope on an objective only when its compromise
reaches beyond the system's own data. The closed list:

| Category token | Meaning |
|---|---|
| `agency-endpoint-delivery` | Delivery, update, or control paths for software installed on agency devices. Compromise executes on endpoints outside the boundary. |
| `cross-system-trust-anchor` | Trust anchors and durable key material honored beyond this system (federation signing, cross-estate credentials). |
| `shared-csp-infrastructure` | Shared provider infrastructure whose blast radius exceeds this authorization boundary. |

Rules:

- A breakout restores `final(o) = CSO(o)` for that objective only.
- A breakout is valid only when `CSO(o)` exceeds the envelope; declaring one
  that does not change the result is an input error (fix the narrative).
- Every breakout carries a written justification and at least one
  manual-review item; a breakout assignment is never `high` confidence.
- Extending this list is a governed edit to this guide and the validators in
  `derive_requirements.py` and `report_confidence.py` — never an ad hoc
  decision during a run.

## Calibration rules

- **Federal-sourced data is the primary High driver.** Direct access to,
  processing of, or transit of actual federal-government-sourced records
  drives C and I toward High.
- **Vulnerability and change data are C:M baseline.** Raw vulnerability scans
  and change-management records rate Moderate confidentiality at most, even
  with strong asset correlation: capable adversaries continuously and
  autonomously probe internet-accessible systems, so possession of a
  vulnerability inventory accelerates them less than it once did. An operator
  may raise this with a written justification; do not raise it by default.
- **Availability means complete logical loss, including durable records.**
  Assess system and agency availability objectives against permanent loss of
  the system and its records — not transient outage tolerance. A
  downtime-tolerant system whose permanent record loss would be a serious
  adverse effect rates A:M or higher. Reserve A:L for genuinely ephemeral or
  reconstructible systems. (This mirrors the component rule: HA never lowers
  AR.)
- **Contamination raises SSO.** Uploads, attachments, free-text fields, and
  feeds from agency systems are where higher-impact content leaks into a
  nominally moderate boundary. Confirmed ingestion paths raise the affected
  SSO objectives; the categorization is usually fine — the boundary
  enforcement is the finding.
- **Agency-device footprint raises the stakes.** Software the system installs
  on agency endpoints (logging, SSO, EDR agents) extends the blast radius
  beyond the system's data and makes the components that ship or control that
  software breakout candidates.

## System-type starting profiles

Starting estimates only — the wizard must confirm or adjust every value.
These are rough profiles by system type, not named products.

| System type | C | I | A | Drivers |
|---|---|---|---|---|
| Project & portfolio management | M | M | M | Portfolio aggregation, PII linkage, durable planning records |
| Legal case management | H | H | M | Privileged/litigation material; legally operative records |
| Electronic medical records | H | H | H | Health records; care delivery cannot pause |
| Security operations / SIEM | M | H | H | Telemetry with identifiers (C:M baseline); alert integrity and protection-critical availability |
| EDR / endpoint management | M | H | H | Agent control channel is code execution on managed endpoints |
| Identity / SSO provider | H | H | H | Credentials and durable trust material |
| Vulnerability management | M | M | M | C:M baseline per calibration |
| Change management / ITSM | M | M | M | Change records drive production change; C:M baseline |
| Document / records management | corpus | M | M | C tracks the stored corpus |
| Learning management | L-M | M | L-M | Mostly public content; workforce rosters raise C |

## Wizard question bank

Ask with the stated why. Unanswered questions never block generation: make the
strongest evidence-backed inference, mark confidence, and add manual-review
items. Never present an inference as an operator attestation.

**Phase A — system identity → SSO**

1. What company and product is this system? May I research it on the public
   web? *(Why: public documentation establishes the product's data profile by
   design; you confirm what I derive.)*
2. Here is the description I derived — what is wrong or missing?
   *(Why: research is an estimate; the system objectives rest on the
   confirmed purpose.)*
3. Which data types are in scope: federal-government-sourced records, PII and
   sensitive PII, CUI, tax information, health information, criminal-justice
   information, legal-privileged material, financial/confidential business
   information, security telemetry, change/configuration data, public
   content? *(Why: each type maps to per-objective drivers under the
   calibration rules.)*
4. Can users or integrations introduce content beyond the designed data model
   — uploads, attachments, free-text fields, email ingest, API feeds from
   agency systems? *(Why: contamination paths are where higher-impact content
   leaks into a moderate boundary; confirmed paths raise the system
   objectives.)*
5. Does the system require software on agency devices (logging, SSO, EDR
   agents)? Which cluster components ship, update, or control them?
   *(Why: endpoint software extends compromise beyond the system's data and
   drives breakout eligibility.)*
6. Are any records legally operative or decision-driving, and what is the
   consequence of permanent record loss — not just downtime?
   *(Why: integrity and availability objectives need more than a
   confidentiality story; availability is assessed against complete logical
   loss.)*

**Phase B — agency → ASO**

7. Which agency or agencies actually use this deployment? "None yet" is fine.
   *(Why: the deploying agency's data propensity sets the per-objective
   ceiling on component requirements.)*
8. If none is definite: which agencies are you targeting? *(Why: target
   agencies guide the data-profile estimate only; they are never evidence of
   multi-agency scope.)*
9. For each agency, here is my per-objective estimate of the data they would
   place in this system, with rationale — confirm or adjust. Which statutory
   or contractual overlays are in scope (tax, criminal-justice, health,
   confidentiality statutes, data-use agreements)? *(Why: overlays are often
   the binding constraint and determine whether an authorizing official can
   accept risk at all.)*
10. Do you know the objective-level categorization from a solicitation,
    privacy impact assessment, or the agency authorization package?
    *(Why: an actual categorization beats any estimate.)*

**Phase C — authorization and scope**

11. What FedRAMP authorization does the offering hold (Ready → A, Low → B,
    Moderate → C, High → D)? *(Why: the Class selects the remediation
    deadline table, and serves as a prior for the divergence protocol — it is
    never authority over the data profile.)*
12. Are multiple agencies served from this cluster, and where is the tenancy
    boundary — whole cluster or per namespace? *(Why: a compromise that
    crosses agencies raises the PAIN tier; namespace tenancy is delivered
    centrally without labeling.)*
13. Should this environment use production-equivalent values, or is it an
    intentionally isolated low-impact environment? *(Why: environment names
    never establish impact.)*

**Phase D — per component** (per coherent workload group, at most five)

14. What could disclosure from this component expose?
15. What trusted action, record, identity, or control could compromise alter?
16. Who is affected by complete logical loss: operators, a bounded subset, or
    all users?
17. Ignoring replicas and failover, is that loss limited, serious, severe, or
    recovery/protection critical?

## Class-vs-data divergence protocol

Per objective, for each agency:

1. Build the ASO estimate blind to Class: research + confirmed data types +
   overlays.
2. Derive the Class prior: D → expect High-impact data in scope; C →
   Moderate; B → Low; A → treat as B unless evidence says otherwise.
3. Compare:
   - **Agreement:** ASO = estimate; record Class as corroborating evidence
     (raises confidence).
   - **Estimate below prior** (moderate data on a High authorization):
     surface the divergence and ask the operator to attest what actually
     lands in this deployment — agencies commonly over-house moderate data on
     High platforms out of risk aversion. An attested lower value wins and is
     recorded operator-confirmed with the divergence preserved. Unanswered:
     the prior (higher value) wins at low confidence with a manual-review
     item. Never lower on an unconfirmed inference.
   - **Estimate above prior** (High data on a Moderate authorization): ASO
     stays at the estimate — Class never caps ASO. Statutory or contractual
     driver: add a prominent manual-review item noting an authorizing
     official cannot accept that risk on someone else's behalf. Agency
     categorization driver: record it as explicit risk-acceptance territory.
4. Record estimate, prior, divergence, resolution, and attestation status in
   `security-objectives.json` under `classPrior.divergences`.

## Multi-agency determination

- Cluster scope, `multiAgency: "true"`: compromise of the cluster can affect
  several agencies and tenancy is not namespace-partitioned.
- Namespace scope: cluster default `"false"` plus `multiAgencyNamespaces`
  globs in the embedded scoring document — central delivery, no labeling.
  Namespace/workload `vdr.fedramp.io/multi-agency` labels stay available as
  operator-applied exceptions, not the default mechanism.
- Never inferred from workload population, and never inferred from a
  target-agency list supplied for data profiling.
- Record scope, values, and justification in `security-objectives.json`.

## Component-objective methodology

Determine each component's role from structural evidence, then select the
strongest credible consequence per objective. Privilege evidence outweighs
product naming.

Evidence to inspect: workload spec and owner references; service account and
RBAC (Roles, ClusterRoles, bindings); Service/Ingress/Gateway routing;
validating and mutating webhooks; host access (privileged mode, host
PID/network/IPC, writable host mounts, runtime sockets, added capabilities);
Secret/ConfigMap/PVC references; node selectors; dependency edges.

Strong privilege signals: broad Secret access, service-account token
creation, IAM/RBAC mutation, `pods/exec`, workload mutation, privileged mode,
host namespaces, writable host mounts, runtime sockets, powerful Linux
capabilities.

Confidentiality (component): what the component can read or is entrusted
with — service payloads, credentials, administrative capability. A bounded
workload credential is not broad privileged access; referencing a Secret does
not make a component a trust anchor.

Integrity (component): what corruption of the component can alter —
authoritative records, configuration, identity, enforcement, releases, shared
foundations, trust roots rate High; bounded processors and scoped writes rate
Medium; advisory output and disposable state rate Low.

Availability (component): the consequence of complete logical loss of the
workload class across all replicas. HA, replicas, zones, disruption budgets,
and autoscalers never lower AR — record them as mitigating evidence outside
the vector. Population informs consequence but is not a multiplier. For
storage drivers, distinguish the driver from the data store: a node-side
driver can still be recovery-critical when its loss prevents mounts,
rescheduling, failover, or restoration.

Telemetry: log processors inherit the most sensitive content logs may
contain; payload-free metrics stay moderate operational metadata. Backups
inherit the protected data type.

Environment names never establish impact. When the operator requires
production parity, classify nonproduction workloads by intended production
data and consequences even when current data is synthetic.

Ownership and mechanism: namespace is not ownership, and ownership never
selects the assignment mechanism. Every inventoried workload gets a central
ConfigMap rule — provider-controlled, customer-controlled, third-party, and
application workloads alike. Prefer exact `nameRules`; use a narrow stable
pattern only when every current match shares the same final vector; use a
`namespaceRule` only when every relevant workload in the namespace shares the
same final vector; treat `kindRules` as exceptional. Give standalone and
Helm-hook Jobs explicit rules; suppress CronJob-owned Jobs (the CronJob is the
durable scorable workload).

## Confidence and review

Confidence measures evidence quality, never impact severity.

| Confidence | Use when | Required output |
|---|---|---|
| high | Direct operator attestation, or structural evidence unambiguously establishes the role and all three objectives. | Evidence recorded; empty manual-review list. |
| medium | Role well supported, but at least one objective relies on a conventional inference about data, authority, population, or consequence. | State the assumption and a concrete verification action. |
| low | Evidence sparse, conflicting, name-based, or dependent on infrastructure outside Kubernetes. | Choose the strongest credible consequence and identify what would change it. |

Never lower a vector because confidence is low. When Medium and High are both
credible, select High and state what evidence would lower it. Breakout
assignments are never high confidence. Reserve `unclassified` for technical
validation failures, never as a substitute for best-effort assignment.

## Artifact schemas

`security-objectives.json` (validated by `report_confidence.py`):

```json
{
  "systemProfile": {
    "product": "generic product name",
    "confirmedDescription": "operator-confirmed purpose and data summary",
    "sso": {"c": {"level": "M", "rationale": "..."},
             "i": {"level": "M", "rationale": "..."},
             "a": {"level": "M", "rationale": "..."}},
    "status": "operator-confirmed",
    "confidence": "high",
    "assumptions": [],
    "manualReview": []
  },
  "agencyProfiles": [
    {"agency": "...", "relationship": "definite",
     "overlays": [{"name": "...", "statuteGrounded": true}],
     "aso": {"c": {"level": "M", "rationale": "..."},
              "i": {"level": "M", "rationale": "..."},
              "a": {"level": "L", "rationale": "..."}},
     "status": "operator-confirmed", "confidence": "high",
     "assumptions": [], "manualReview": []}
  ],
  "classPrior": {"class": "C", "divergences": []},
  "sso": {"c": "M", "i": "M", "a": "M"},
  "aso": {"c": "M", "i": "M", "a": "L"},
  "envelope": {"c": "M", "i": "M", "a": "L"},
  "ceilingMode": "semi-hard",
  "multiAgencyDetermination": {
    "scope": "cluster", "clusterDefault": false,
    "justification": "...", "status": "operator-confirmed",
    "confidence": "high", "assumptions": [], "manualReview": []}
}
```

Rules: top-level `envelope` must equal per-objective `min(sso, aso)`;
`systemProfile.sso` levels must match top-level `sso`; with definite agency
profiles, top-level `aso` equals the per-objective max over them; namespace
scope requires non-empty `multiAgencyNamespaces`.

`assignment-coverage.json`: top-level `context`, `inventoryTotal`,
`assignments`, `configurationAssumptions`, `summary`. One assignment per
inventoried workload:

```json
{"namespace": "...", "kind": "...", "name": "...",
 "componentObjectives": {"c": {"level": "H", "reason": "..."},
                          "i": {"level": "H", "reason": "..."},
                          "a": {"level": "M", "reason": "..."}},
 "vector": "M/M/L",
 "securityRequirements": "cr-m_ir-m_ar-l",
 "capped": {"c": true, "i": true, "a": true},
 "breakouts": [],
 "resolutionSource": "nameRule",
 "status": "agent-inferred",
 "confidence": "medium",
 "evidence": "...",
 "assumptions": ["..."],
 "manualReview": ["..."]}
```

The gate enforces the envelope math, capped-flag accuracy, label/vector
consistency, breakout legitimacy, the inventory equation, and the confidence
contract.

## Runtime mechanics

- The label key is delivered by renaming the plugin's archetype key inside the
  embedded scoring document:

  ```yaml
  labelKeys:
    archetype: vdr.fedramp.io/security-requirements
  ```

  This works with the current plugin and retires `vdr.fedramp.io/asset-archetype`
  for the cluster (single-string field; no dual-key support). Legacy archetype
  labels found in inventory are inert — report them as stale cleanup items.
- Label values are dot-free opaque catalog keys `cr-[lmh]_ir-[lmh]_ar-[lmh]`.
  Dots are reserved by the plugin for the legacy compositional grammar; never
  emit a dotted value. Every value used by a label or rule must exist in the
  `archetypes` catalog; always emit all 27 entries via
  `derive_requirements.py --emit-catalog`.
- The rule field name remains `archetype:` inside `nameRules`/`kindRules`/
  `namespaceRules` — a plugin schema constant, not a vocabulary statement.
- Resolution precedence is unchanged: workload label → namespace label →
  nameRule → kindRule → namespaceRule → `unclassified` H/H/H fail-safe. An
  explicit label with a value missing from the catalog short-circuits to the
  fail-safe; it never falls through to a quieter rule.
- The envelope exists only at generation time. Nothing at runtime caps a
  vector, and the H/H/H fail-safe is untouched.
- `humanReviewCompleted` is a human-only attestation marker in the ConfigMap:
  always generated `"false"`, comment-fenced, never read, reported,
  summarized, analyzed, or modified by AI agents or automated tooling, and
  never carried forward from a previous ConfigMap.
```

- [ ] **Step 2: Verify structure**

```bash
grep -c '^## ' skills/generate-security-requirements-configmap/references/security-objectives-guide.md
grep -n 'agency-endpoint-delivery\|cross-system-trust-anchor\|shared-csp-infrastructure' skills/generate-security-requirements-configmap/references/security-objectives-guide.md | head -4
```

Expected: 13 `##` sections (Contents + 12 numbered); the three breakout tokens present.

- [ ] **Step 3: Mirror, verify, commit**

```bash
rsync -a --delete skills/generate-security-requirements-configmap/ .agents/skills/generate-security-requirements-configmap/
diff -r skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap && echo MIRRORS-OK
git add skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap
git commit -m "Add security objectives derivation guide"
```

---

### Task 6: `SKILL.md` for the new skill

**Files:**
- Create: `skills/generate-security-requirements-configmap/SKILL.md`

**Interfaces:**
- Consumes: `scripts/list_workloads.py --context <ctx>`, `scripts/derive_requirements.py --emit-catalog|--derive`, `scripts/report_confidence.py <coverage> <objectives>`, `references/security-objectives-guide.md` (all exist from Tasks 2-5).
- Produces: the skill entrypoint referenced by README (Task 9) and by the old skill's deprecation note (Task 8) under the exact name `generate-security-requirements-configmap`.

- [ ] **Step 1: Write SKILL.md with this exact content**

```markdown
---
name: generate-security-requirements-configmap
description: Generate the trivy-plugin-vdr vdr-fedramp scoring ConfigMap by deriving per-component security-requirements vectors from system, agency, and component security objectives; runs a transparent wizard covering system purpose and data profile, agency data propensity with a Class divergence protocol, and multi-agency scope, inventories Kubernetes workloads read-only, combines objectives with envelope math and enumerated breakouts, writes security-objectives and assignment-coverage justification JSONs with confidence and manual-review annotations, and never applies anything. Supersedes generate-vdr-configmap and its archetype decision traces.
---

# Generate Security Requirements ConfigMap

Interview the operator, research the system and agencies (with consent),
inspect the selected Kubernetes cluster read-only, and write the governed
scoring artifacts consumed by `trivy-plugin-vdr`. In commands below, resolve
`<skill-dir>` to the directory containing this file.

Read `references/security-objectives-guide.md` completely before the wizard.
It defines the three-vector model, combination math, breakout categories,
calibration rules, the question bank with the transparency text, the
divergence protocol, the component methodology, and the artifact schemas.

## Ground rules

- Run only `kubectl config` and `kubectl get`. Never run `exec`, `apply`,
  `label`, `patch`, `edit`, or `delete`.
- Write only under `./vdr-configmap-output/`. The operator reviews and applies
  the output manually or through GitOps.
- Web research requires operator consent. Present derived descriptions and
  profiles for confirmation; the operator's corrections win. If consent is
  declined, derive profiles from operator description alone and lower
  confidence accordingly.
- Ask the wizard questions with their stated why, but do not let incomplete
  answers stop artifact generation after a successful inventory. Make the
  strongest evidence-backed best guess, state every assumption, and mark its
  confidence. Never present an inference as an operator attestation.
- Account for every inventoried workload. Ordinary uncertainty is not an
  unresolved exception: assign the most defensible vector, lower its
  confidence, and flag it for review. Never omit a workload silently.
- Confidence never lowers a vector, and HA never lowers AR.
- The agency envelope is a semi-hard ceiling: components exceed it only
  through the closed breakout categories, each with a written justification
  and a manual-review flag, never at high confidence.
- For a fresh evaluation, do not read or reuse the existing `vdr-fedramp`
  ConfigMap. Existing labels may be reported, but are not attestations unless
  reconfirmed. Never carry `humanReviewCompleted` forward: generation always
  emits `"false"`, and the value is never mentioned in any report, JSON, or
  terminal output.
- Never retrieve Secret resources or values. Reference names visible in
  workload specs are sufficient evidence.
- No real product, vendor, or agency names in any reusable skill content.
  Runtime artifacts for the operator's own cluster naturally contain their
  real names.

## Workflow

### 1. Confirm the target context

Run `kubectl config current-context`, show the value, and obtain explicit
confirmation before inventory. State that cluster access remains read-only.
Pass that exact reviewed name to every inventory query.

### 2. System profile -> SSO

Run wizard Phase A (guide section 6): product identity and research consent,
description confirmation, data-type checklist, contamination paths,
agency-device footprint, integrity/availability posture. Apply the
calibration rules (guide section 4): federal-sourced data drives High;
vulnerability and change data are C:M baseline; availability is judged
against complete logical loss including durable records; confirmed
contamination paths raise SSO. Start from the system-type profile table and
adjust with evidence. Record everything in `security-objectives.json`
(`systemProfile` plus top-level `sso`).

### 3. Class and agencies -> ASO

Run wizard Phases B and C questions 11: identify deploying agencies (or
target agencies as data-profile guides only), research each with consent,
present per-objective estimates with rationale and overlays for confirmation,
and map the authorization to Class (Ready A, Low B, Moderate C, High D). Run
the divergence protocol (guide section 7) per objective: estimates are built
blind to Class, divergences are surfaced transparently, attestations resolve
them, silence resolves to the higher value. Multiple definite agencies take
the per-objective max. No agencies at all: ASO defaults to SSO at low
confidence with a manual-review item. Record `agencyProfiles`, `classPrior`
with divergences, and top-level `aso`.

### 4. Multi-agency determination

Run wizard question 12. Decide cluster scope (`multiAgency: "true"`) or
namespace scope (cluster default `"false"` plus `multiAgencyNamespaces`
globs). Never infer from workload population or from a target-agency list.
Record the determination with justification. If unanswered, emit the
fail-closed provisional value (`"true"` at cluster scope) with low confidence
and a manual-review item.

### 5. Compute the envelope

`envelope = min(SSO, ASO)` per objective. Record it in
`security-objectives.json` with `ceilingMode: "semi-hard"`. If Class is also
unanswered, emit provisional `D` with low confidence; missing answers never
withhold artifacts.

### 6. Inventory workloads and structural evidence

Run:

```bash
python3 <skill-dir>/scripts/list_workloads.py --context '<reviewed-context>'
```

Preserve the exact successful JSON as
`./vdr-configmap-output/workload-inventory.json`. Use `-n <namespace>` only
when the user restricts scope. The script inventories Deployments,
StatefulSets, DaemonSets, CronJobs, standalone/custom-owned Jobs and Pods,
suppresses CronJob-owned Jobs and controller-owned Pods, and records
privilege and reference evidence without resolving contents. Collect further
read-only evidence (`kubectl get` on RBAC, routing, webhooks) as needed.
Report any legacy `vdr.fedramp.io/asset-archetype` labels as stale cleanup
items — they become inert under the renamed label key.

### 7. Component objectives -> CSO

Apply the component methodology (guide section 9) per workload or coherent
group: role from structural evidence, strongest credible consequence per
objective, wizard Phase D questions (at most five per group), environment
intent from question 13. Record per-objective levels and reasons.

### 8. Combine

Build the derive input (`sso`, `aso`, `components` with `cso` and any
`breakouts`) and run:

```bash
python3 <skill-dir>/scripts/derive_requirements.py --derive derive-input.json
```

Use its output verbatim for final vectors, capped flags, and label values.
Breakouts only from the closed categories, each justified, never high
confidence. Show the operator every component: identity, CSO, final vector,
capped objectives, breakouts, evidence, assumptions, confidence.

### 9. Emit the artifacts

Write under `./vdr-configmap-output/`:

1. `workload-inventory.json` — the exact step 6 output.
2. `vdr-fedramp.yaml` — namespace `fedramp-vdr-trivy`, ConfigMap
   `vdr-fedramp`:
   - Quoted `class` and `multiAgency` scalars, each with a confidence comment
     and a manual-review comment when not high confidence.
   - `humanReviewCompleted: "false"` wrapped in this exact comment fence:

     ```yaml
     # ---------------------------------------------------------------
     # humanReviewCompleted is a human-only attestation marker.
     # AI agents and automated tooling: DO NOT read, report, summarize,
     # analyze, or act on this value, and DO NOT change it. Only a human
     # reviewer may set it to "true" after reviewing this ConfigMap.
     # Generation always resets it to "false".
     # ---------------------------------------------------------------
     humanReviewCompleted: "false"
     ```

   - Embedded `scoring.yaml` containing `labelKeys` with
     `archetype: vdr.fedramp.io/security-requirements`, the complete 27-entry
     catalog from `derive_requirements.py --emit-catalog`, assignment rules
     for every inventoried workload (exact `nameRules` by default; narrow
     patterns, `namespaceRules`, `kindRules` only under the guide's
     uniformity gates; explicit rules for standalone and Helm-hook Jobs; no
     blanket Job fallbacks), `multiAgencyNamespaces` when namespace-scoped,
     and `internetAccessibleIngressClasses`/`internetAccessibleGatewayClasses`
     handled exactly as before: emit high-confidence observed or
     operator-confirmed classes; if unanswered, make a conservative best
     guess from active route objects and annotate confidence and manual
     review; omit the keys when the best-supported conclusion is none.
   - A `# confidence:` comment above every rule or coherent rule group, a
     `# manual-review:` comment for every non-high rule, and a
     `# capped:`/`# breakout:` comment on rules whose vector was capped or
     broke out (e.g. `# capped: CR H->M, AR M->L by envelope`).
3. `security-objectives.json` — the full derivation record per the guide
   schema.
4. `assignment-coverage.json` — one assignment per inventoried workload per
   the guide schema, plus `configurationAssumptions` for provisional Class,
   multi-agency, or ingress assumptions, and a `summary` with counts by
   namespace, resolution source, status, confidence, capped, and breakout.

If the operator explicitly requests direct-label overrides, also emit
`label-overrides.sh` beginning with `FOR OPERATOR REVIEW AND EXECUTION`,
pinned to the reviewed `--context`, using the
`vdr.fedramp.io/security-requirements` key; for CronJobs put the label in
CronJob `metadata.labels` or
`spec.jobTemplate.spec.template.metadata.labels`, never
`spec.jobTemplate.metadata.labels`.

Do not put PAIN word thresholds in the ConfigMap. If the user supplies a
proprietary-term deny-list, scan generated files case-insensitively.

### 10. Validate without touching the cluster

- Parse the outer YAML and embedded `scoring.yaml`.
- Verify every label value matches `cr-[lmh]_ir-[lmh]_ar-[lmh]`, is dot-free,
  and has a catalog entry whose cr/ir/ar match its encoding; all 27 entries
  present.
- Verify `humanReviewCompleted` is present, `"false"`, and comment-fenced;
  never print its value anywhere.
- Verify confidence comments on `class`, `multiAgency`, emitted or
  provisionally omitted internet-accessibility keys, and every rule;
  manual-review comments wherever confidence is not high.
- Resolve every inventory entry through actual precedence (workload label ->
  namespace label -> nameRule -> kindRule -> namespaceRule -> fail-safe);
  fail if any workload resolves to `unclassified` or an explicit
  security-requirements label carries a value missing from the catalog.
- Verify the inventory equation and that every emitted rule matches at least
  one inventoried workload unless operator-attested forward-looking.
- Run the mandatory gate; a nonzero exit is a validation failure:

  ```bash
  python3 <skill-dir>/scripts/report_confidence.py \
    ./vdr-configmap-output/assignment-coverage.json \
    ./vdr-configmap-output/security-objectives.json
  ```

  It re-verifies the envelope math, capped flags, breakout legitimacy, and
  confidence contract, and prints the manual-review list, capped components,
  and breakouts (explicit `none` when empty).
- When a sibling `trivy-plugin-vdr` checkout is available, prefer an offline
  parser/smoke test against that implementation; treat invalid-cluster-config
  warnings as failures even on exit zero.
- When `label-overrides.sh` exists, run `bash -n` on it.
- Keep the `skills/` and `.agents/skills/` copies byte-identical.
- Never execute any generated artifact.

### 11. Handoff

Report the inventory total, operator-confirmed and agent-inferred counts,
confidence counts, capped-component count, the breakout list, and any
precedence conflicts. Repeat the non-high-confidence manual-review list in
the terminal. Never state the `humanReviewCompleted` value. Tell the operator
to review all four files, apply the ConfigMap manually or through GitOps, and
flip `humanReviewCompleted` to `"true"` only as a deliberate human action
after review. Re-run the skill after estate, system, agency, Class, scope, or
reviewed-assumption changes.
```

- [ ] **Step 2: Verify references resolve**

```bash
cd skills/generate-security-requirements-configmap
ls references/security-objectives-guide.md scripts/list_workloads.py scripts/derive_requirements.py scripts/report_confidence.py
grep -c 'humanReviewCompleted' SKILL.md
cd ../..
```

Expected: all four files listed; `humanReviewCompleted` appears at least 4 times.

- [ ] **Step 3: Mirror, verify, commit**

```bash
rsync -a --delete skills/generate-security-requirements-configmap/ .agents/skills/generate-security-requirements-configmap/
diff -r skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap && echo MIRRORS-OK
git add skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap
git commit -m "Add generate-security-requirements-configmap skill instructions"
```

---

### Task 7: Example ConfigMap + structural tests

**Files:**
- Create: `skills/generate-security-requirements-configmap/assets/vdr-fedramp.example.yaml`
- Test: `tests/test_example_configmap.py`

**Interfaces:**
- Consumes: `derive_requirements.py` label grammar and catalog format (Task 2); the humanReviewCompleted fence text (Task 6).
- Produces: the fictional example the SKILL and README reference.

- [ ] **Step 1: Write the failing test**

Create `tests/test_example_configmap.py`:

```python
import itertools
import re
import unittest
from pathlib import Path

EXAMPLE = (Path(__file__).resolve().parents[1] / "skills"
           / "generate-security-requirements-configmap" / "assets"
           / "vdr-fedramp.example.yaml")


class ExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = EXAMPLE.read_text(encoding="utf-8")

    def test_all_27_catalog_entries_present_once(self):
        for c, i, a in itertools.product("lmh", repeat=3):
            key = f'"cr-{c}_ir-{i}_ar-{a}":'
            self.assertEqual(self.text.count(key), 1, key)
        self.assertEqual(self.text.count("lens: requirements"), 27)

    def test_label_key_rename_present(self):
        self.assertIn("archetype: vdr.fedramp.io/security-requirements", self.text)

    def test_human_review_marker_fenced_false(self):
        self.assertIn('humanReviewCompleted: "false"', self.text)
        self.assertIn("human-only attestation marker", self.text)
        self.assertIn("DO NOT read, report, summarize", self.text)

    def test_rules_use_dot_free_label_values(self):
        for match in re.finditer(r"archetype:\s*([\w.\-/]+)", self.text):
            value = match.group(1)
            if value.startswith("vdr.fedramp.io/"):
                continue  # the labelKeys rename line
            self.assertRegex(value, r"^cr-[lmh]_ir-[lmh]_ar-[lmh]$")

    def test_no_real_names(self):
        for banned in ("Clarity", "Broadcom", "Rally", "NIH", "CFTC", "USPTO",
                       "Ohio", "Patlytics", "DCEG", "DAU"):
            self.assertNotIn(banned, self.text)

    def test_scalars_quoted_with_confidence_comments(self):
        self.assertIn('class: "C"', self.text)
        self.assertIn('multiAgency: "false"', self.text)
        self.assertGreaterEqual(self.text.count("# confidence:"), 6)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest discover -s tests -v 2>&1 | tail -3`
Expected: ERROR — example file missing.

- [ ] **Step 3: Write the example**

Create `skills/generate-security-requirements-configmap/assets/vdr-fedramp.example.yaml`:

```yaml
# Fictional example: a project & portfolio management SaaS at FedRAMP
# Moderate, deployed for a single agency. Envelope M/M/L (SSO M/M/M capped by
# agency availability L). Values are security-requirements catalog keys; the
# derivation rationale lives in security-objectives.json and
# assignment-coverage.json, not in the labels.
apiVersion: v1
kind: Namespace
metadata:
  name: fedramp-vdr-trivy
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vdr-fedramp
  namespace: fedramp-vdr-trivy
data:
  # confidence: high | operator-confirmed FedRAMP Moderate authorization
  class: "C"
  # confidence: high | operator-confirmed single-agency deployment
  multiAgency: "false"

  # ---------------------------------------------------------------
  # humanReviewCompleted is a human-only attestation marker.
  # AI agents and automated tooling: DO NOT read, report, summarize,
  # analyze, or act on this value, and DO NOT change it. Only a human
  # reviewer may set it to "true" after reviewing this ConfigMap.
  # Generation always resets it to "false".
  # ---------------------------------------------------------------
  humanReviewCompleted: "false"

  scoring.yaml: |
    labelKeys:
      # Retires vdr.fedramp.io/asset-archetype for this cluster; legacy
      # archetype labels become inert and should be cleaned up.
      archetype: vdr.fedramp.io/security-requirements

    archetypes:
      "cr-l_ir-l_ar-l":
        {lens: requirements, cr: L, ir: L, ar: L}
      "cr-l_ir-l_ar-m":
        {lens: requirements, cr: L, ir: L, ar: M}
      "cr-l_ir-l_ar-h":
        {lens: requirements, cr: L, ir: L, ar: H}
      "cr-l_ir-m_ar-l":
        {lens: requirements, cr: L, ir: M, ar: L}
      "cr-l_ir-m_ar-m":
        {lens: requirements, cr: L, ir: M, ar: M}
      "cr-l_ir-m_ar-h":
        {lens: requirements, cr: L, ir: M, ar: H}
      "cr-l_ir-h_ar-l":
        {lens: requirements, cr: L, ir: H, ar: L}
      "cr-l_ir-h_ar-m":
        {lens: requirements, cr: L, ir: H, ar: M}
      "cr-l_ir-h_ar-h":
        {lens: requirements, cr: L, ir: H, ar: H}
      "cr-m_ir-l_ar-l":
        {lens: requirements, cr: M, ir: L, ar: L}
      "cr-m_ir-l_ar-m":
        {lens: requirements, cr: M, ir: L, ar: M}
      "cr-m_ir-l_ar-h":
        {lens: requirements, cr: M, ir: L, ar: H}
      "cr-m_ir-m_ar-l":
        {lens: requirements, cr: M, ir: M, ar: L}
      "cr-m_ir-m_ar-m":
        {lens: requirements, cr: M, ir: M, ar: M}
      "cr-m_ir-m_ar-h":
        {lens: requirements, cr: M, ir: M, ar: H}
      "cr-m_ir-h_ar-l":
        {lens: requirements, cr: M, ir: H, ar: L}
      "cr-m_ir-h_ar-m":
        {lens: requirements, cr: M, ir: H, ar: M}
      "cr-m_ir-h_ar-h":
        {lens: requirements, cr: M, ir: H, ar: H}
      "cr-h_ir-l_ar-l":
        {lens: requirements, cr: H, ir: L, ar: L}
      "cr-h_ir-l_ar-m":
        {lens: requirements, cr: H, ir: L, ar: M}
      "cr-h_ir-l_ar-h":
        {lens: requirements, cr: H, ir: L, ar: H}
      "cr-h_ir-m_ar-l":
        {lens: requirements, cr: H, ir: M, ar: L}
      "cr-h_ir-m_ar-m":
        {lens: requirements, cr: H, ir: M, ar: M}
      "cr-h_ir-m_ar-h":
        {lens: requirements, cr: H, ir: M, ar: H}
      "cr-h_ir-h_ar-l":
        {lens: requirements, cr: H, ir: H, ar: L}
      "cr-h_ir-h_ar-m":
        {lens: requirements, cr: H, ir: H, ar: M}
      "cr-h_ir-h_ar-h":
        {lens: requirements, cr: H, ir: H, ar: H}

    # Central assignment rules. Unknown future components stay fail-safe
    # (unclassified H/H/H). Vectors are final = min(CSO, envelope) with
    # envelope M/M/L; caps and breakouts are annotated for review.
    nameRules:
      # confidence: high | system-of-record database; CSO H/H/M
      # capped: CR H->M, IR H->M, AR M->L by envelope (agency data profile)
      - {namespace: app, match: portfolio-db, archetype: cr-m_ir-m_ar-l}
      # confidence: high | private API over bounded records; CSO M/M/M
      # capped: AR M->L by envelope
      - {namespace: app, match: portfolio-api, archetype: cr-m_ir-m_ar-l}
      # confidence: medium | ships and controls agents installed on agency
      # devices; CSO M/H/L with an integrity breakout
      # breakout: IR agency-endpoint-delivery — compromise executes on
      # agency endpoints beyond this boundary
      # manual-review: confirm the endpoint update channel and its signing
      - {namespace: app, match: endpoint-agent-updater, archetype: cr-m_ir-h_ar-l}
      # confidence: high | cluster DNS; CSO L/H/H
      # capped: IR H->M, AR H->L by envelope
      - {namespace: kube-system, match: cluster-dns, archetype: cr-l_ir-m_ar-l}
      # confidence: medium | payload-free metrics collector; CSO M/M/M
      # capped: AR M->L by envelope
      # manual-review: verify the collector cannot ingest logs or payloads
      - {namespace: monitoring-system, match: "metrics-agent*", archetype: cr-m_ir-m_ar-l}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v 2>&1 | tail -3`
Expected: `OK`.

- [ ] **Step 5: Mirror, verify, commit**

```bash
rsync -a --delete skills/generate-security-requirements-configmap/ .agents/skills/generate-security-requirements-configmap/
diff -r skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap && echo MIRRORS-OK
git add skills/generate-security-requirements-configmap .agents/skills/generate-security-requirements-configmap tests/test_example_configmap.py
git commit -m "Add security-requirements ConfigMap example"
```

---

### Task 8: Deprecate `generate-vdr-configmap`

**Files:**
- Modify: `skills/generate-vdr-configmap/SKILL.md:1-8` (frontmatter description + blockquote after the H1)
- Modify: `.agents/skills/generate-vdr-configmap/SKILL.md` (same edit, byte-identical)

**Interfaces:**
- Consumes: the new skill name `generate-security-requirements-configmap` (Task 6).
- Produces: deprecation language README (Task 9) echoes.

- [ ] **Step 1: Edit the frontmatter description**

In `skills/generate-vdr-configmap/SKILL.md`, the description currently begins:

```yaml
description: Generate or update the trivy-plugin-vdr vdr-fedramp scoring ConfigMap from FedRAMP Class, agency scope, and compositional CR/IR/AR decision traces; ...
```

Prepend the deprecation sentence so it begins:

```yaml
description: Deprecated in favor of generate-security-requirements-configmap, which derives security-requirements vectors from system, agency, and component security objectives. Generate or update the trivy-plugin-vdr vdr-fedramp scoring ConfigMap from FedRAMP Class, agency scope, and compositional CR/IR/AR decision traces; ...
```

(Keep the rest of the description unchanged.)

- [ ] **Step 2: Add the blockquote directly under the H1**

After the line `# Generate VDR ConfigMap`, insert:

```markdown

> **Deprecated:** This skill is superseded by
> `generate-security-requirements-configmap`, which derives per-component
> security-requirements vectors from system, agency, and component security
> objectives and uses the `vdr.fedramp.io/security-requirements` label
> vocabulary. Use this skill only to maintain clusters that still resolve the
> legacy `vdr.fedramp.io/asset-archetype` vocabulary.
```

- [ ] **Step 3: Mirror, verify, commit**

```bash
cp skills/generate-vdr-configmap/SKILL.md .agents/skills/generate-vdr-configmap/SKILL.md
diff -r skills .agents/skills && echo MIRRORS-OK
git add skills/generate-vdr-configmap/SKILL.md .agents/skills/generate-vdr-configmap/SKILL.md
git commit -m "Deprecate generate-vdr-configmap in favor of the security-requirements skill"
```

---

### Task 9: README update

**Files:**
- Modify: `README.md:31-45` (the `generate-vdr-configmap` section) and `README.md:106-114` (consumption section)

**Interfaces:**
- Consumes: skill names and artifact names from Tasks 6-8.

- [ ] **Step 1: Insert the new skill section and demote the old**

Replace the current `### generate-vdr-configmap → the vdr-fedramp ConfigMap` section (README.md lines 31-45) with:

```markdown
### `generate-security-requirements-configmap` → the `vdr-fedramp` ConfigMap

Derives a per-component **Security Requirements** vector (CR/IR/AR) from three
per-objective inputs: the **system's** security objectives (what the product
holds by design, confirmed by the operator from consented web research), the
deploying **agency's** security objectives (the data that agency would
actually place in the system — objective-level, never the FIPS 199 high-water
mark, with the Certification Class used as a prior rather than authority), and
each **component's** security objectives from read-only structural evidence.
The envelope `min(system, agency)` caps component vectors; enumerated breakout
categories (agency-endpoint delivery paths, cross-system trust anchors, shared
CSP infrastructure) may exceed it with written justification and manual-review
flags. Emits the `vdr-fedramp` ConfigMap (label key
`vdr.fedramp.io/security-requirements`, dot-free `cr-*_ir-*_ar-*` values, a
human-only `humanReviewCompleted` marker) plus `security-objectives.json` and
`assignment-coverage.json` justification records. Every decision carries
confidence; medium/low decisions, capped components, and breakouts are printed
for review.

### `generate-vdr-configmap` → the `vdr-fedramp` ConfigMap (deprecated)

> **Status:** Superseded by `generate-security-requirements-configmap`. Use it
> only to maintain clusters that still resolve the legacy
> `vdr.fedramp.io/asset-archetype` vocabulary.

Interviews the operator to capture the scoring attestations: the FedRAMP
**Certification Class**, the **agency scope** (single/multi-agency), and
per-workload compositional decision traces producing deterministic CR/IR/AR
vectors. Emits a central `vdr-fedramp` ConfigMap rule for every workload plus
an assignment-coverage ledger with confidence and manual-review reporting.
```

- [ ] **Step 2: Update the consumption section**

In `## How the ConfigMaps are consumed`, replace the sentence
"`vdr-fedramp` drives PAIN scoring and `VDR-TFR-PVR` remediation deadlines (Certification Class, agency scope, archetype rules)."
with:
"`vdr-fedramp` drives PAIN scoring and `VDR-TFR-PVR` remediation deadlines (Certification Class, agency scope, and security-requirements rules; legacy archetype rules remain supported for clusters generated by the deprecated skill)."

- [ ] **Step 3: Verify and commit**

```bash
grep -n 'generate-security-requirements-configmap' README.md | head -3
git add README.md
git commit -m "Document the security-requirements ConfigMap skill in the README"
```

Expected: at least two hits (section header and deprecation note).

---

### Task 10: Full-repo validation sweep

**Files:** none created; validation only.

- [ ] **Step 1: Run the full test suite**

Run: `python3 -m unittest discover -s tests -v 2>&1 | tail -5`
Expected: `OK`, zero failures/errors.

- [ ] **Step 2: Compile every script in both trees**

```bash
python3 -m py_compile \
  skills/generate-security-requirements-configmap/scripts/*.py \
  .agents/skills/generate-security-requirements-configmap/scripts/*.py
echo "compile-exit=$?"
```

Expected: `compile-exit=0`.

- [ ] **Step 3: Whole-tree mirror check and clean status**

```bash
diff -r skills .agents/skills && echo MIRRORS-OK
git status --short
```

Expected: `MIRRORS-OK`; `git status --short` empty (everything committed).

- [ ] **Step 4: Real-name scan over the new skill**

```bash
grep -riE 'clarity|broadcom|rally|patlytics|nih|cftc|uspto|ohio|dceg|\bdau\b' \
  skills/generate-security-requirements-configmap && echo "FAIL: real names found" || echo "NAME-SCAN-OK"
```

Expected: `NAME-SCAN-OK`.

- [ ] **Step 5: Optional plugin smoke test (best-effort)**

If `/Users/matthewvenne/github/trivy-plugin-vdr` exists and builds, follow that
repo's README to run a manifest-mode scan with
`--config-map skills/generate-security-requirements-configmap/assets/vdr-fedramp.example.yaml`
against any sample manifest, and treat any "cluster FedRAMP ConfigMap is
invalid" warning as a failure. If the plugin cannot be built in this
environment, record that the smoke test was skipped in the final report — do
not fake it.
```
