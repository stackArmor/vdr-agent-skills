---
name: generate-cloud-vdr-config
description: Generate or fully reassess vdr-cloud.yaml from read-only GCP/AWS discovery, including GKE infrastructure, secrets, KMS, IAM and workload/data resources. Assign independently dimensional CR/IR/AR profiles with confidence and a coverage ledger. For coverage-only updates preserving existing scores, use update-cloud-vdr-config instead. Never change infrastructure or publish without explicit authorization.
---

# Generate Cloud VDR Config

Interview the operator, inventory the selected GCP projects and AWS accounts
read-only, and write the central `vdr-cloud.yaml` assignment surface plus an
inventory baseline and a coverage ledger. This is the cloud analogue of
`generate-k8s-vdr-configmap`: it does for buckets, VMs, managed SQL, and the other
CIS Foundations-addressed cloud families what that skill does for Kubernetes
workloads. In commands below, resolve `<skill-dir>` to the directory containing
this file. Read `references/cloud-config-schema.md` and
`references/managed-resource-patterns.md` before authoring rules.

For an additive coverage update that must not reassess existing scores, use
the separate `../update-cloud-vdr-config/SKILL.md` workflow instead.

## Ground rules

- Run only read-only cloud verbs: `list`, `describe`, `get`,
  `sts get-caller-identity`, `gcloud config get-value`, `gcloud auth list`,
  `gcloud projects list`, `gcloud asset list`. Never change cloud infrastructure,
  replication, secret values, key state or IAM permissions. If the user explicitly
  requests policy publication, treat that as a separate step: validate locally,
  back up the exact previous object generation, upload only the named policy with
  a generation precondition, and compare the downloaded result.
- Write only under `./vdr-cloud-output/`. The operator reviews and versions the
  output manually or through GitOps. Always start with a clean directory: remove
  or archive any existing `./vdr-cloud-output/` before a run so that stale
  `scope-*.json` files do not contaminate the inventory merge, and artifacts from
  prior runs do not influence the current evaluation.
- For an incremental update, preserve existing rules and attestations, inventory
  every retained scope, and add only evidence-backed assignments. Historical
  assignments are retained context, not fresh operator attestations.
- For a fresh evaluation, do not read or adopt existing `assignment-plan.json`
  or `vdr-cloud.yaml` files. Run the full operator interview fresh for Class,
  agency scope, and consequence; never treat historical artifacts or prior runs
  as current operator attestations.
- **TSW consumes `vdr-cloud.yaml`; `trivy-plugin-vdr` does not.** Verify the
  consumer's supported types and collection capabilities before claiming runtime
  coverage. Published rules for undeployed support remain pending rollout.
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

Read `../generate-k8s-vdr-configmap/references/archetype-guide.md` completely before
assigning profiles. It defines direct vectors, the optional archetype system,
allowed trace reasons, the five-question interview, availability calibration,
all 27 vector combinations, and examples. The governed trace registry and its
`reason_codes.py` classifier are shared, not duplicated.

For control assets, read `references/control-assets.md` before assigning profiles.
For GKE clusters/node pools, fleet memberships, or Binary Authorization policies,
read `references/gke-infrastructure.md`. These cloud resources belong in
`vdr-cloud.yaml`; Pods, Deployments, namespaces and other Kubernetes objects
belong in the ConfigMap workflow. Inventory also covers subnets and load-balancer
proxies affected by infrastructure configuration findings.
Do not score every secret, key or IAM object alike or treat a service account as
a secret. Discovery reads resource/IAM-policy metadata only; never secret versions,
key material, VM metadata values or function environment values.
Group service-account keys under their owning account for scoring, while keeping
each full key URI in inventory and the coverage ledger for precise SCC joins.
Inherit the owner's complete profile after explicit key overrides/rules and
before scope/global defaults; do not emit redundant per-key rules. See the
control-asset reference for scoped owner matching and credential-specific AR.

Group KMS CryptoKeys under their exact owning KeyRing for SIP and multiAgency.
Explicit key labels/rules win per attribute; otherwise inherit the ring's
resolved values before scope/global defaults. Keep full key paths in inventory
and record parent resolution evidence; do not emit redundant per-key rules.

## Workflow

### 1. Establish scopes

Ensure `./vdr-cloud-output/` is empty or newly created before starting:

```bash
mkdir -p ./vdr-cloud-output
# If re-running, remove or archive previous run artifacts first
```

Ask whether this is a single-cloud account/project or multi-cloud account/project run. Each confirmed GCP project or
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

Merge only the per-scope files generated during this run into the coverage baseline:

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
per group. Read `../generate-k8s-vdr-configmap/references/archetype-guide.md`
completely first. At most five questions per group, with evidence-backed
best-effort inference and confidence marking when the operator delegates.

- **Environment intent (Staging vs. Production):** In ThreatAlert (TSW), staging
  and non-production accounts/projects are tracked separately from production
  and can be excluded from official FedRAMP authorization package reporting.
  Staging findings do not count against official FedRAMP compliance. However,
  mapping staging/non-production resources with production-equivalent profiles
  is strongly recommended so teams triage and remediate vulnerabilities under the
  exact same PAIN severity and timeline pressures they will face in production.
  If the operator chooses an isolated non-production profile, assign low-impact
  values (`nonproduction` / `cr-l_ir-l_ar-l`). Environment names alone never
  establish low impact.
- **Multi-Agency scope:** Explain that `multiAgency` is largely an architectural
  consequence of their multi-tenancy strategy (dedicated single-tenant deployment
  vs shared multi-tenant infrastructure). After setting the scope- or global-level
  baseline, follow up by asking if specific VPCs/subnets, shared databases, or
  storage buckets deviate from that default, attaching `multiAgency: true/false`
  to the narrowest rule covering those exceptions.
- **Availability calibration:** HA never lowers AR — evaluate the consequence
  of the resource class being logically unavailable across all replicas;
  redundancy is a mitigating control outside the requirement vector.
- **Confidence:** Confidence describes evidence quality; it never lowers
  CR/IR/AR. When several outcomes remain credible, choose the strongest and
  state what would change it.

### 4b. Ask once about strict IP allowlists

TSW derives internet reachability from firewall, route, and load-balancer
evidence. It reports an asset **reachable** whenever it can prove some internet
host reaches an open port — including when the firewall admits only a handful
of public CIDRs, because that is still reachable as a matter of network fact.
Whether such an allowlist is tight enough that the asset should not count as
internet-reachable is a judgement no evaluator can make, so ask for it.

Ask once, for the whole run: *are any of these assets reachable from the public
internet only through a strict source-IP allowlist that you maintain?*
- *Provide context if requested:*
  1. *Operator declaration vs. hard heuristics:* Automated scanners cannot
     determine whether a list of source IPs is "safe." Hardcoded heuristic limits
     on IP counts or CIDR mask sizes (e.g. requiring `/32`s or rejecting `/24`s)
     fail in practice because federal agency customers or enterprise tenants
     often legitimately own an entire public `/24` or larger dedicated to
     corporate or campus VPN egress. The operator must make the authoritative
     declaration that the source IPs represent an approved, restricted
     population rather than general public access.
  2. *FedRAMP VDR PAIN timeline impact:* Setting `internetReachable: "false"`
     moves findings from the IRV (Internet Reachable Vulnerability) column to the
     NIRV (Non-Internet Reachable Vulnerability) column in the FedRAMP VDR
     PAIN-based remediation timeline matrix. A false declaration creates a
     false NIRV negative that 3PAO assessors will cite.
  3. *No raw CIDRs needed:* The operator does not need to supply a dump of raw
     CIDRs. They only need to name the allowlist, state where it is enforced
     (e.g., security group, firewall rule, or WAF IP-set), and attest that it is
     strictly maintained.
  4. *What qualifies vs. what doesn't:* Only strict source-IP allowlists qualify
     (even when enforced on a WAF). WAF managed rule sets (OWASP Core), DDoS
     protections (Cloudflare, AWS Shield), API rate limiting, basic
     authentication, or geo-blocking alone NEVER make a public endpoint
     non-internet-reachable.

Then, for each asset class the operator confirms:
- Emit `internetReachable: "false"` with a non-empty
  `internetReachableJustification` on the narrowest rule that covers exactly
  those assets. It goes on a rule — never at `defaults` or scope level, which
  both scripts refuse.
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
  Use `match` for globs or `matchRegex` for a whole-identifier regular expression,
  never both. A grouped rule may cover resources only when every current match
  shares the assigned profile and review rationale; always pin `type`. Explicit
  alternation is useful for a finite group without admitting unrelated identities.
  Review the expanded match set in the ledger, including unexpected matches;
  names alone do not establish equal authority or availability requirements.
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

Regex rules require `regex>=2024.11.4` in the Python environment running the
renderer, validator and delta helper; glob-only use remains standard-library
matching. Both the skill and TSW use the same bounded full-match implementation.
See the schema reference for regex syntax, YAML escaping and safety limits.

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
(tag override → nameRule → tagRule → networkRule → typeRule → owning SA SIP for
SA keys, or owning KeyRing SIP/multiAgency for CryptoKeys → scope → defaults →
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
consumer caveat plainly: TSW consumes `vdr-cloud.yaml`, but `trivy-plugin-vdr`
does not; runtime coverage requires the deployed collectors and type support.
List any failed scopes and any existing-tag override
conflicts. Tell the operator to review all three artifacts and version them
manually or through the owning GitOps repository. Re-run the skill after estate,
Class, or scope changes.
