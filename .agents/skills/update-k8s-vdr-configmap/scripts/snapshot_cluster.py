#!/usr/bin/env python3
"""Capture one reviewed ConfigMap and sanitized workload inventory read-only."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

INVENTORY_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "generate-k8s-vdr-configmap/scripts/list_workloads.py"
)


def capture(
    *,
    context,
    output_directory,
    configmap_namespace="fedramp-vdr-trivy",
    configmap_name="vdr-fedramp",
    namespace=None,
    baseline_file=None,
):
    destination = Path(output_directory)
    if destination.exists():
        raise ValueError(
            "output directory already exists; choose a fresh run directory"
        )
    if baseline_file:
        baseline = Path(baseline_file).read_text(encoding="utf-8")
        source = str(Path(baseline_file).resolve())
    else:
        result = subprocess.run(
            [
                "kubectl",
                "--context",
                context,
                "get",
                "configmap",
                configmap_name,
                "--namespace",
                configmap_namespace,
                "-o",
                "yaml",
            ],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if result.returncode or not result.stdout.strip():
            raise ValueError(
                "deployed ConfigMap could not be read; ask the operator for the current baseline"
            )
        baseline = result.stdout
        source = f"{context}:{configmap_namespace}/{configmap_name}"
    command = [sys.executable, str(INVENTORY_SCRIPT), "--context", context]
    if namespace:
        command.extend(["-n", namespace])
    result = subprocess.run(
        command, capture_output=True, text=True, timeout=300, check=False
    )
    if result.returncode:
        raise ValueError("workload discovery failed; no complete snapshot was written")
    inventory = json.loads(result.stdout)
    if inventory.get("context") != context or not isinstance(
        inventory.get("workloads"), list
    ):
        raise ValueError("inventory context/shape mismatch")
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "baseline-configmap.yaml").write_text(baseline, encoding="utf-8")
    (destination / "workload-inventory.json").write_text(
        result.stdout, encoding="utf-8"
    )
    (destination / "provenance.json").write_text(
        json.dumps(
            {
                "context": context,
                "baselineSource": source,
                "scope": inventory.get("scope"),
                "inventoryTotal": len(inventory["workloads"]),
                "readOnly": True,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True)
    parser.add_argument("--output-directory", required=True)
    parser.add_argument("--configmap-namespace", default="fedramp-vdr-trivy")
    parser.add_argument("--configmap-name", default="vdr-fedramp")
    parser.add_argument("--namespace")
    parser.add_argument("--baseline-file")
    args = parser.parse_args()
    try:
        output = capture(
            context=args.context,
            output_directory=args.output_directory,
            configmap_namespace=args.configmap_namespace,
            configmap_name=args.configmap_name,
            namespace=args.namespace,
            baseline_file=args.baseline_file,
        )
        print(f"Read-only snapshot written to {output}")
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"snapshot failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
