---
name: update-k8s-vdr-configmap
description: Refresh coverage of the deployed vdr-fedramp ConfigMap using the current kubectl context or an operator-supplied baseline. Diff read-only workload inventory against effective assignments, classify only unscored workloads, and produce an additive ConfigMap plus a preservation report without re-evaluating existing scores or applying cluster changes.
---

# Update Kubernetes VDR coverage

Use this for additive maintenance of an existing scoring ConfigMap. It is
separate from fresh generation and full impact reassessment. `<skill-dir>` is
this directory; choose a fresh `<run-dir>` under `./vdr-configmap-update-output/`.
Keep the sibling generation skills installed from this package: inventory,
profile registry and matching helpers are shared rather than forked.

## Pin the current context and baseline

Run `kubectl config current-context`, show the current kubectx and confirm the
intended target. Do not switch context or fetch replacement cloud credentials.
Pin the reviewed `--context` on every cluster query. Use the cluster's current
credentials (including its existing gcloud/AWS exec-provider configuration);
do not log in, assume a new role or edit kubeconfig.

Read the deployed `fedramp-vdr-trivy/vdr-fedramp` ConfigMap by default; honor an
operator-specified namespace/name. If it is absent, inaccessible, or the user
wants a GitOps baseline, prompt for the current manifest/file and record its
source and confirmed cluster association. Never interpret a failed read as an
empty ConfigMap or switch to a full reassessment. If live and GitOps copies
differ, show the difference and ask which baseline to maintain.

Snapshot the baseline and workloads with the read-only helper:

```bash
python3 <skill-dir>/scripts/snapshot_cluster.py \
  --context '<reviewed-context>' --output-directory <run-dir>
```

For another deployed target, add `--configmap-namespace <ns>` and
`--configmap-name <name>`; for a confirmed local baseline add
`--baseline-file <manifest>`. Restrict inventory with `--namespace <ns>` only
when requested. The directory must not already exist. A snapshot failure is
incomplete discovery, not authoritative absence. The helper stores the exact
baseline and invokes the sibling generator's sanitized workload inventory,
which includes standalone Jobs/custom-owned Pods but suppresses CronJob-owned
Jobs and duplicate controller Pods. Never retrieve Secrets or literal env data.

## Diff effective coverage first

```bash
python3 <skill-dir>/scripts/coverage_diff.py --mode k8s \
  --baseline <run-dir>/baseline-configmap.yaml \
  --inventory <run-dir>/workload-inventory.json \
  --output <run-dir>/coverage-diff.json
```

An optional `--previous-inventory` identifies new workload identities only when
its reviewed context and namespace scope match. Without it, report coverage
gaps, not proven newly created workloads.

Mechanical resolution follows workload/template SIP labels, namespace labels,
name rules, kind rules, namespace rules, then the intentional default. This is
coverage replay, **not** re-evaluation of a covered workload's CR/IR/AR. New
workloads already covered by a valid namespace/pattern/default remain untouched.
An absent or `unclassified` profile is a gap. Unknown explicit labels block
lower-precedence ConfigMap rules; report them for separately authorized repair
instead of claiming a new rule will fix them. Existing assignments may be
listed but must not be re-interviewed, re-scored or refreshed as attestations.

## Classify only gaps; preserve everything else

Read `../generate-k8s-vdr-configmap/references/archetype-guide.md` completely
before classifying `missing-assignment` workloads. Reuse its independently
dimensional interview, trace validation, role/privilege evidence and confidence
guidance only for those gaps. Existing Class, multi-agency scope, named catalog,
ceiling and ingress/allowlist declarations are frozen historical configuration.
Do not invent new taxonomy reasons or touch labels as part of this update.

Preserve baseline comments and old rule order. Append namespace-scoped exact
name rules where safe; for generated Job names, use narrow kind/name/namespace
rules only when all matching missing workloads share the decision. Name rules
are not kind-scoped in the plugin, so check every kind with that name before
adding one. Do not use a broad namespace/kind fallback to make coverage pass.
New rules must not touch any already-covered workload, even if the proposed
profile happens to be identical. Never remove stale rules or not-observed
workloads. A blocked addition requires operator direction, not a rewritten old
rule or a silent full generation pass.

Write `vdr-fedramp.yaml`, a unified diff, gap-only decision ledger with
profile/vector/evidence/confidence/manual review, and full coverage report. Keep
all ConfigMap data outside its selected embedded scoring document unchanged;
inside that document, only append assignment rules. Server-managed metadata may
be omitted from the reviewable manifest, but the ConfigMap target must stay the
same. Do not create a new Namespace or apply anything.

```bash
python3 <skill-dir>/scripts/coverage_diff.py --mode k8s \
  --baseline <run-dir>/baseline-configmap.yaml \
  --inventory <run-dir>/workload-inventory.json \
  --candidate <run-dir>/vdr-fedramp.yaml \
  --output <run-dir>/preservation-report.json
```

Require exit zero. The guard rejects rule rewrites/reordering/removals, changed
scalars/defaults/catalog/ceilings/attestations, additions matching already-covered
workloads, and remaining gaps. It validates syntax/known profiles, not impact
correctness. Parse with the actual trivy-plugin-vdr implementation offline when
available, especially for noncanonical configuration or glob syntax. Unknown
runtime overrides make resolution uncertain: ask for the effective scoring
configuration rather than guessing. The helper needs PyYAML; use an existing
environment with it or report the missing parser.

## Handoff

Report covered-unchanged, gaps, proposed additions, blocked labels/configuration,
and manual-review decisions; explicitly say existing scores were not
re-evaluated. If there are no gaps, report no changes. Keep artifacts local for
operator/GitOps review. Never run `apply`, `patch`, `label`, `edit`, `exec`, or
`delete`. Commit/push/PR actions require a separate user request; this skill
never deploys a ConfigMap.
