#!/usr/bin/env python3
"""Validate compositional VDR profile traces and report derived CR/IR/AR."""

import argparse
import itertools
import re
import sys


DISCLOSURE_REASONS = {
    "public-content": "L",
    "opaque-transit": "L",
    "routing-metadata": "L",
    "synthetic-data": "L",
    "service-content": "M",
    "ops-metadata": "M",
    "security-evidence": "M",
    "control-metadata": "M",
    "scoped-access": "M",
    "federal-records": "H",
    "regulated-data": "H",
    "restricted-evidence": "H",
    "root-secrets": "H",
    "privileged-access": "H",
}

TRUSTED_CHANGE_REASONS = {
    "advisory-output": "L",
    "opaque-forwarding": "L",
    "disposable-state": "L",
    "isolated-testing": "L",
    "bounded-processing": "M",
    "scoped-write": "M",
    "record-keeping": "M",
    "coordination-state": "M",
    "authoritative-record": "H",
    "config-control": "H",
    "identity-control": "H",
    "security-enforcement": "H",
    "release-control": "H",
    "foundation-control": "H",
    "trust-anchor": "H",
}

OUTAGE_REASONS = {
    "deferrable-work": "L",
    "optional-tooling": "L",
    "nonproduction": "L",
    "bounded-service": "M",
    "operations-support": "M",
    "shared-degradation": "M",
    "change-deferred": "M",
    "shared-critical-path": "H",
    "mission-essential": "H",
    "protection-critical": "H",
    "recovery-critical": "H",
}

CANONICAL = {
    "cr": {"L": "public-content", "M": "service-content", "H": "regulated-data"},
    "ir": {"L": "advisory-output", "M": "bounded-processing", "H": "authoritative-record"},
    "ar": {"L": "deferrable-work", "M": "bounded-service", "H": "shared-critical-path"},
}

LABEL_VALUE = re.compile(r"^[A-Za-z0-9](?:[-A-Za-z0-9_.]*[A-Za-z0-9])?$")


def classify(trace):
    parts = trace.split(".")
    if len(parts) != 3:
        raise ValueError(
            "%r must contain exactly three dot-separated reasons" % trace
        )
    disclosure, trusted_change, outage = parts
    if disclosure not in DISCLOSURE_REASONS:
        raise ValueError("unknown disclosure reason %r in %r" % (disclosure, trace))
    if trusted_change not in TRUSTED_CHANGE_REASONS:
        raise ValueError(
            "unknown trusted-change reason %r in %r" % (trusted_change, trace)
        )
    if outage not in OUTAGE_REASONS:
        raise ValueError("unknown outage reason %r in %r" % (outage, trace))
    if len(trace) > 63 or not LABEL_VALUE.fullmatch(trace):
        raise ValueError(
            "%r is not a valid Kubernetes label value of at most 63 characters" % trace
        )
    return (
        DISCLOSURE_REASONS[disclosure],
        TRUSTED_CHANGE_REASONS[trusted_change],
        OUTAGE_REASONS[outage],
    )


def canonical_traces():
    traces = []
    for cr, ir, ar in itertools.product("LMH", repeat=3):
        traces.append(
            ".".join(
                (CANONICAL["cr"][cr], CANONICAL["ir"][ir], CANONICAL["ar"][ar])
            )
        )
    return traces


def emit_yaml(traces):
    classified = [(trace, classify(trace)) for trace in traces]
    print("validatedProfiles:")
    for trace, (cr, ir, ar) in classified:
        print('  - securityImpactProfile: "%s"' % trace)
        print("    derivationMethod: decision-trace")
        print("    vector: {cr: %s, ir: %s, ar: %s}" % (cr, ir, ar))


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Validate <disclosure>.<trusted-change>.<outage> decision traces "
            "and report their independently derived CR/IR/AR profiles."
        )
    )
    parser.add_argument(
        "--cover-27",
        "--all-27",
        dest="cover_27",
        action="store_true",
        help="add canonical traces for CR/IR/AR permutations not already represented",
    )
    parser.add_argument("traces", nargs="*", help="additional confirmed traces")
    args = parser.parse_args()

    try:
        ordered = []
        for trace in args.traces:
            if trace not in ordered:
                ordered.append(trace)
        if args.cover_27:
            represented = {classify(trace) for trace in ordered}
            for trace in canonical_traces():
                vector = classify(trace)
                if vector not in represented:
                    ordered.append(trace)
                    represented.add(vector)
        if not ordered:
            parser.error("provide at least one trace or use --cover-27")
        emit_yaml(ordered)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
