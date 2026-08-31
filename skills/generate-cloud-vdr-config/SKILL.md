---
name: generate-cloud-vdr-config
description: Generate or update the central vdr-cloud.yaml CloudResourceScoringConfig for non-Kubernetes cloud resources from read-only gcloud/aws discovery of CIS Foundations-addressed GCP and AWS resource families; assign FedRAMP Class, agency scope, and independently dimensional CR/IR/AR security-impact profiles through name, tag, network, and type rule matching with family-tier precedence; materialize managed-resource patterns as reviewable medium-confidence rules; demote per-resource vdr.fedramp.io/* tags to overrides; emit a coverage ledger with confidence and manual-review reporting; validate full coverage without cloud access; and never apply anything. The document is a proposed integration contract that no current scanner consumes.
---

# Generate Cloud VDR Config

Interview the operator, inventory the selected GCP projects and AWS accounts
read-only, and write the central `vdr-cloud.yaml` assignment surface plus an
inventory baseline and a coverage ledger. This is the cloud analogue of
`generate-vdr-configmap`: it does for buckets, VMs, managed SQL, and the other
CIS Foundations-addressed cloud families what that skill does for Kubernetes
workloads. In commands below, resolve `<skill-dir>` to the directory containing
this file. Read `references/cloud-config-schema.md` and
`references/managed-resource-patterns.md` before authoring rules.

## Ground rules

- Run only read-only cloud verbs: `list`, `describe`, `get`,
  `sts get-caller-identity`, `gcloud config get-value`, `gcloud auth list`,
  `gcloud projects list`, `gcloud asset list`. Never run any mutating verb and
  never apply anything to a cloud account.
- Write only under `./vdr-cloud-output/`. The operator reviews and versions the
  output manually or through GitOps.
- **`vdr-cloud.yaml` is a proposed integration contract. `trivy-plugin-vdr`
  does not consume it today.** State this in every handoff, exactly as the
  `TerraformAssetClassifications` sidecar does. Until plugin-side consumption
  lands, the document is a reviewed record of impact assignments, not a runtime
  input.
- Treat the document as the **primary** assignment surface for every inventoried
  cloud resource. Per-resource `vdr.fedramp.io/*` tags remain valid but are
  demoted to the exception/override mechanism.
- Ask for Class, agency scope, and per-resource consequence, but do not let
  incomplete answers stop generation after a successful inventory. Make the
  strongest evidence-backed best guess, state every assumption, and mark its
  confidence. When Class or agency scope is unattested, emit fail-closed
  provisional values (class `"D"`, multiAgency `"true"`) with confidence and
  manual-review annotations; missing answers never withhold the artifact. Never
  present an inference as an operator attestation.
- Account for every inventoried resource. Ordinary uncertainty is not an
  unresolved exception: assign the strongest credible profile, lower its
  confidence, and flag it for review. Reserve failure for technical validation
  errors only.
- Existing `vdr.fedramp.io/*` tags found during discovery are evidence, not
  attestation. Report them as override agreements or conflicts; do not treat
  them as operator attestations unless reconfirmed.
- Never write secret-bearing config into artifacts: no instance user-data, no
  function environment values, no credentials. Reference names are sufficient
  evidence.

## Security-impact-profile schema

Every rule's `securityImpactProfile` is an independently dimensional CR/IR/AR
profile in **canonical dotted form**: a direct vector (`cr-h_ir-m_ar-l`), a
compositional decision trace with exactly three segments
(`<disclosure>.<trusted-change>.<dependency>`), or a named archetype from the
optional catalog. Prefer a compositional trace. Provider label encodings (GCP
`vdr_fedramp_io_*` keys, `__` trace separators, Azure `.` keys) apply only to
actual cloud tags and are decoded at discovery — they never appear inside
`vdr-cloud.yaml`.

Read `../generate-vdr-configmap/references/archetype-guide.md` completely before
assigning profiles. It defines direct vectors, the optional archetype system,
allowed trace reasons, the five-question interview, availability calibration,
all 27 vector combinations, and examples. The governed trace registry and its
`reason_codes.py` classifier are shared, not duplicated.

## Workflow

### 1. Establish scopes

Ask whether this is a single- or multi-scope run. Each confirmed GCP project or
AWS account becomes one `scopes:` entry.

- **AWS:** ask which named CLI profiles to use, one per account. Validate each
  with `aws sts get-caller-identity --profile <p>`, show the resolved account ID
  and ARN, and confirm the profile-to-account mapping before any inventory.
  Every call pins `--profile`. The skill never assumes roles itself;
  cross-account access is whatever the operator's profiles already do. Profile
  names stay in the inventory ledger, never in `vdr-cloud.yaml` (they are local
  machine config).
- **GCP:** offer `gcloud projects list` to enumerate accessible projects, let
  the operator select the in-scope set, and pin `--project` on every call.

A scope whose inventory fails is **excluded** from the document and reported as
failed — never emitted as a silently partial block.

### 2. Inventory resources read-only

Run the inventory script once per scope, restricted to the CIS
Foundations-addressed families. GCP:

```bash
python3 <skill-dir>/scripts/inventory_cloud_resources.py \
  --provider gcp --project <p> \
  --output ./vdr-cloud-output/scope-gcp-<p>.json
```

It prefers Cloud Asset Inventory (`gcloud asset list`) and falls back to
per-service commands when the Asset API is unavailable, recording an explicit
degraded-inventory warning that names what could not be enumerated (add
`--no-asset-api` to force the fallback). AWS:

```bash
python3 <skill-dir>/scripts/inventory_cloud_resources.py \
  --provider aws --profile <p> --region <r> [--region <r2> ...] \
  --output ./vdr-cloud-output/scope-aws-<account>.json
```

Merge the per-scope files into the coverage baseline:

```bash
python3 <skill-dir>/scripts/inventory_cloud_resources.py \
  --merge ./vdr-cloud-output/scope-*.json \
  --output ./vdr-cloud-output/resource-inventory.json
```

Preserve the exact merged JSON as `./vdr-cloud-output/resource-inventory.json`;
never reconstruct or filter it when calculating coverage. Each resource records
type, primary identifier, region/zone, tags/labels, network attachment where
applicable, decoded `vdrTags`, and matched `builtinPatterns` — never user-data
or environment blobs. Surface every degraded-inventory warning; never let a gap
be silent.

### 3. Mine tags and patterns

Use each scope's `tagSummary` (key, value distribution, coverage) to propose
`tagRules` only where a coherent operator taxonomy already exists (`data-class`,
`env`, `owner`, ...). Report every existing `vdr.fedramp.io/*` tag in `vdrTags`
as a potential override (agreement or conflict). Resources annotated with
`builtinPatterns` are pre-classified at medium confidence against the catalog's
default trace and inherit its manual-review notes; read
`references/managed-resource-patterns.md` for each pattern's rationale.

### 4. Interview per coherent group

Cluster the remaining resources into coherent groups (type + naming pattern +
shared tags + network), then run the archetype guide's five-question interview
per group. Read `../generate-vdr-configmap/references/archetype-guide.md`
completely first. At most five questions per group, with evidence-backed
best-effort inference and confidence marking when the operator delegates.

Environment names never establish impact — classify a nonproduction resource by
its intended production data and consequence. HA never lowers AR — evaluate the
consequence of the resource class being logically unavailable across all
replicas; redundancy is a mitigating control outside the requirement vector.
Confidence describes evidence quality; it never lowers CR/IR/AR. When several
outcomes remain credible, choose the strongest and state what would change it.

### 4b. Ask once about strict IP allowlists

TSW derives internet reachability from firewall, route, and load-balancer
evidence. It reports an asset **reachable** whenever it can prove some internet
host reaches an open port — including when the firewall admits only a handful
of public CIDRs, because that is still reachable as a matter of network fact.
Whether such an allowlist is tight enough that the asset should not count as
internet-reachable is a judgement no evaluator can make, so ask for it.

Ask once, for the whole run: *are any of these assets reachable from the public
internet only through a strict source-IP allowlist that you maintain?* Then, for
each asset class the operator names:

- Emit `internetReachable: "false"` with a non-empty
  `internetReachableJustification` on the narrowest rule that covers exactly
  those assets. It goes on a rule — never at `defaults` or scope level, which
  both scripts refuse.
- **WAF, L7 filtering, OWASP rule sets, and DDoS protection alone never
  qualify.** Only sufficiently strict IP whitelisting does, though a WAF may be
  the component that implements the allowlist. If the operator offers a WAF as
  the reason, say this and ask again for the allowlist.
- Write the justification for an assessor: name the allowlist, say where it is
  enforced, and say what it admits. TSW publishes it verbatim next to the
  evaluated verdict the attestation displaced.
- Carry a `# manual-review:` line requiring re-attestation whenever the
  allowlist widens, and record the attestation in `configurationAssumptions`.

Never infer this attestation, and never emit it to quiet an `unknown`
reachability verdict — an operator confirming a specific allowlist is the only
thing that justifies it. Emitting nothing is always safe: TSW keeps its own
verdict. `internetReachable: "true"` needs no justification, but it is also
rarely worth emitting, since it agrees with the conservative default.

### 5. Author the assignment plan

Write `./vdr-cloud-output/assignment-plan.json` (shape in
`references/cloud-config-schema.md`). Choose the narrowest rule family that
correctly covers each coherent group:

- Prefer `nameRules` with exact primary identifiers (see the identifier table).
  A name glob may cover a group only when every current match shares the
  assigned profile; always pin `type`.
- Use `tagRules` only over a verified-coherent operator taxonomy.
- Use `networkRules` only when every relevant network-attached resource on that
  VPC/subnet shares the profile.
- Use `typeRules` only when a whole resource family in the scope is coherent.
- Materialize each `builtinPatterns` match as an explicit commented rule
  (`builtinPattern` id, medium confidence, manual-review note); never assume one
  silently.

Prefer fail-loud over broad `securityImpactProfile` defaults at the scope or
global level: a resource that no rule matches should fail validation, not
inherit a broad default. Every rule and every `class`/`multiAgency` value gets a
confidence level; every non-high item gets at least one concrete manual-review
string. Attributes resolve independently — a one-line `nameRule` can flip
`multiAgency` or `internetReachable` for one resource while its SIP resolves
from a broader rule.

### 6. Emit and validate

Render the document and author the coverage ledger, then validate without cloud
access:

```bash
python3 <skill-dir>/scripts/render_cloud_config.py \
  --plan ./vdr-cloud-output/assignment-plan.json \
  --output ./vdr-cloud-output/vdr-cloud.yaml
```

Author `./vdr-cloud-output/assignment-coverage.json` with one assignment entry
per inventoried resource (`scope`, `type`, `identifier`,
`securityImpactProfile`, `derivationMethod`, `vector`, `resolutionSource`,
`multiAgency`, `multiAgencySource`, `internetReachable`,
`internetReachableSource`, `internetReachableJustification`, `status`,
`confidence`, `evidence`,
`assumptions`, `manualReview`) plus `configurationAssumptions` and `summary`.
Give every non-high entry at least one concrete manual-review item; record
provisional Class/multiAgency values in `configurationAssumptions`. Then:

```bash
python3 <skill-dir>/scripts/validate_cloud_config.py \
  --plan ./vdr-cloud-output/assignment-plan.json \
  --inventory ./vdr-cloud-output/resource-inventory.json \
  --coverage ./vdr-cloud-output/assignment-coverage.json \
  --rendered ./vdr-cloud-output/vdr-cloud.yaml
```

The validator re-derives every assignment through the actual precedence chain
(tag override → nameRule → tagRule → networkRule → typeRule → scope → defaults →
fail-loud), validates every SIP value against the shared governed registry,
checks the inventory equation, detects zero-match and shadowed rules, flags a
`networkRule` on a non-network-attached type, cross-checks the coverage ledger,
confirms the rendered file re-renders identically, and prints the mandatory
confidence report. **Treat any nonzero exit as a validation failure.**

When the user supplies a proprietary-term deny-list, scan all generated files
(`vdr-cloud.yaml`, `resource-inventory.json`, `assignment-plan.json`,
`assignment-coverage.json`) case-insensitively for those terms and parameterize
or remove any hit before handoff. Keep the `skills/` and `.agents/skills/`
copies byte-identical. Never execute any generated artifact.

An operator-facing reference document, `assets/vdr-cloud.example.yaml`, shows a
fictional rendered two-scope document.

## Handoff

Report totals by scope, status (`operator-confirmed`, `agent-inferred`,
`builtin-pattern`), and confidence. Repeat the non-high-confidence manual-review
list in the terminal; do not hide it behind the YAML. State the
proposed-integration-contract caveat plainly: no current scanner consumes
`vdr-cloud.yaml`. List any failed scopes and any existing-tag override
conflicts. Tell the operator to review all three artifacts and version them
manually or through the owning GitOps repository. Re-run the skill after estate,
Class, or scope changes.
