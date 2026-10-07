---
name: update-cloud-vdr-config
description: Refresh coverage of an existing vdr-cloud.yaml using current gcloud credentials and operator-selected AWS CLI profiles. Diff read-only inventory against existing assignments, evaluate only missing resources or new scopes, preserve existing scores and attestations, and produce an additive candidate and preservation report. Not a full reassessment or automatic publication workflow.
---

# Update cloud VDR coverage

Use this for incremental coverage maintenance, not re-scoring an estate. In
commands, `<skill-dir>` is this directory and `<run-dir>` is a fresh directory
under `./vdr-cloud-update-output/`. Do not delete or overwrite previous runs.
Keep this skill together with the sibling generation skills shipped in this
package; its helper reuses their matching and governed profile registry.

## Establish the baseline and credentials

Ask for the authoritative existing `vdr-cloud.yaml`: local/GitOps path or GCS
URI. Do not silently use a prior generated candidate. For GCS, inspect the
object generation, download that exact generation, and record URI/generation
in the run's provenance. Never publish during discovery. If repository and live
policy disagree, show that difference and ask which baseline to maintain.
Without an existing baseline, ask for one; fresh generation is a separate task.

Use the current gcloud login; do not log in, activate another configuration,
mint/print tokens, enable APIs, or change IAM. Show the active configuration,
account, default project and any configured impersonation using read-only
`gcloud config configurations list`, `gcloud auth list` and `gcloud config
get-value`. Ask the operator to confirm the GCP projects, starting with the
baseline's scopes and offering additional projects. Do not assume every visible
project is in scope. Pin `--project` on each query and retain the reviewed
configuration/account/impersonation environment for the run. If identity changes,
stop and reconfirm; successful access is not authorization to expand scope.

Ask whether AWS accounts are in scope. If yes, ask which named AWS CLI profiles
and regions to use; `aws configure list-profiles` may offer names, not secrets.
Verify each selected profile with `aws sts get-caller-identity --profile <p>`,
show the account/ARN and confirm the mapping before inventory. Never fall back
to the default profile, assume a role independently, or query unselected
accounts/regions. Profile names belong in local provenance, not policy rules.
Existing AWS scopes without a confirmed profile remain unchanged and are
reported as not inventoried, never removed.

## Discover and diff before evaluating

Read the sibling `../generate-cloud-vdr-config/SKILL.md` for discovery and schema
details, but use this skill's incremental boundaries instead of its full
interview/generation workflow. Run its `scripts/inventory_cloud_resources.py`
once per confirmed scope, writing only this run's exact outputs. Pass explicit
GCP projects or AWS profiles/regions. Merge an explicit list of those files;
never merge a glob containing prior runs. Keep failed/degraded scope warnings.
Read metadata only: no Secret versions, key material, environment values,
instance user-data, or credential files.

Run the offline delta helper:

```bash
python3 <skill-dir>/scripts/coverage_diff.py --mode cloud \
  --baseline <run-dir>/baseline-vdr-cloud.yaml \
  --inventory <run-dir>/resource-inventory.json \
  --output <run-dir>/coverage-diff.json
```

Optionally supply `--previous-inventory <trusted-prior-snapshot>` to identify
new identities. Without it, call findings coverage gaps, not proven newly
created resources. Identity includes project/account, type and primary
identifier; use full KMS/key/role paths and scoped IAM-binding identities.
GKE clusters, node pools, fleet memberships, Binary Authorization policies,
subnets and load-balancer proxies are cloud resource types. Read the generator's
`references/gke-infrastructure.md` for their identifiers and policy evidence.
Covered clusters retain their existing SIP even when a new SCC hardening finding
appears; finding severity or an intentional exception does not justify rescoring
the asset. Add assignments only for uncovered infrastructure identities.

Mechanically replay rule/override precedence; do not reassess the consequences
or CR/IR/AR of covered resources. A new resource already covered by an existing
valid pattern, label, or intentional default is **covered-unchanged**, not a
reason to add another score. Report label-only coverage separately if relevant.
`unclassified`/absent profiles are gaps. Unknown profiles, broken overrides or
invalid existing metadata are blockers for separately authorized repair, not
permission to rewrite them. Not-observed resources and stale rules are reports
only; do not delete anything on the basis of this run.

Service-account keys without explicit key rules inherit their owning account's
existing complete SIP. Report them as covered-unchanged when that parent resolves;
do not re-interview or re-score the parent. Keep each key's full URI in the
inventory. Missing/ambiguous owners are gaps, not permission to hide them with
defaults. Follow the control-asset reference for any genuinely new key exception.
Do not consolidate/remove old explicit key rules in this additive workflow:
that requires a separately authorized policy migration.

KMS CryptoKeys without explicit key values inherit SIP and multiAgency from
their exact owning KeyRing, independently per attribute. Replay existing ring
rules/labels without reassessing the ring; newly observed keys are
covered-unchanged when they resolve. Missing/ambiguous/unresolved rings are gaps
or blockers, not permission to hide them with defaults. Preserve existing
explicit key rules; consolidating them requires separate authorization.

## Evaluate gaps and emit an additive candidate

Only interview/classify entries marked `missing-assignment` or `missing-scope`.
Read `../generate-k8s-vdr-configmap/references/archetype-guide.md` completely
before assigning profiles; use the existing governed taxonomy. For controls,
read `../generate-cloud-vdr-config/references/control-assets.md`; for managed
patterns, read its `references/managed-resource-patterns.md`. Score contents,
authority and logical outage dependencies independently; HA does not lower AR.
New decisions get evidence, confidence and concrete manual-review notes.

Preserve baseline text/comments, rule order, named catalog, defaults, existing
Class/multi-agency values, ceilings and reachability attestations. Append narrow
typed name rules or verified-coherent tag rules only for gaps, and append new
project/account scopes only when confirmed. Never add broad SIP defaults to
hide gaps. Do not add reachability overrides in this coverage-only workflow.
New name rules may use `matchRegex` instead of glob `match`; follow the
generator's whole-identifier regex contract and inspect every current match.
The helper replays existing regex rules mechanically without re-evaluating their
scores. It rejects new regex rules touching covered resources. Do not consolidate
existing entries into a regex during coverage maintenance; that is a separately
requested equivalence-checked policy refactor. Regex use additionally requires
`regex>=2024.11.4` in the helper's Python environment.
An already-matching name rule may prevent an appended rule resolving a gap;
report that blocker rather than altering the existing rule. Do not rescore
existing profiles to fit a new resource or change the taxonomy.

Write `vdr-cloud.yaml`, a baseline-to-candidate unified diff, a gap-only
decision ledger (profile/vector/evidence/confidence/manual review), and the
full mechanical coverage/preservation report. Then:

```bash
python3 <skill-dir>/scripts/coverage_diff.py --mode cloud \
  --baseline <run-dir>/baseline-vdr-cloud.yaml \
  --inventory <run-dir>/resource-inventory.json \
  --candidate <run-dir>/vdr-cloud.yaml \
  --output <run-dir>/preservation-report.json
```

Require exit zero. The guard rejects edits/removals/reordering of old rules,
changed defaults/catalog/scalars, new rules touching already-covered resources,
and unresolved gaps. Validate the candidate with TSW's actual offline consumer
when available; discovery coverage is not proof of deployed collector support.
Historical zero-match rules are retained context, not failures to "fix" by
deletion; apply new-rule match checks only to additions. PyYAML is needed by the
delta helper; use an existing environment with it or report the missing parser.

## Handoff and publication boundary

Report covered-unchanged, gap, proposed-addition and blocker counts by scope,
new/unknown identities, every failed/degraded scope, and manual-review decisions.
State explicitly that existing scores were preserved, not re-evaluated. TSW
consumes this policy; trivy-plugin-vdr does not. No changes should be emitted
when there are no gaps. Partial discovery cannot establish exhaustive coverage.

All outputs stay local. A request to update coverage is not authorization to
upload, apply infrastructure, commit, push, or create a PR. If the operator
separately requests policy publication, use the generation/backup/verification
procedure in the cloud generator, refusing a stale-baseline overwrite. GitOps
publication must preserve unrelated work and use a separately authorized PR.
