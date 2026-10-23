# vdr-agent-skills

> Repository rename: this project was previously named `trivy-plugin-vdr-skills`.
> GitHub preserves redirects for the old repository URL and Git clients, but new
> links and checkouts should use `stackArmor/vdr-agent-skills` (hyphens between
> all three words).

The VDR Agent Skills generate the asset classification that
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr) uses for
FedRAMP VDR/VER scoring. Run them with your AI agent of choice: they interview
you about your system, read your environment's metadata with read-only CLI
commands, and produce **Security Impact Profiles (SIPs)** for the assets in
scope. **Nothing is ever applied to a cluster or cloud account by an agent.**

## Getting started: install and run the skills

### 1. Check the prerequisites

| Requirement | Details | Needed for |
|-------------|---------|------------|
| `python3` (>= 3.8) | Runs the inventory/capture scripts. Standard library only — no `pip install` needed. | All skills |
| `kubectl` (authenticated) | Network access to the cluster API. **Read-only RBAC is sufficient** — `get`/`list` on workloads and namespaces (and, for `capture-dataflow-beta`, NetworkPolicies, mesh resources, and Secrets). | Kubernetes skills (`generate-k8s-vdr-configmap`, `update-k8s-vdr-configmap`, `capture-dataflow-beta`) |
| `gcloud`, `aws`, and/or `az` CLI (authenticated, read-only) | `list`/`describe`/`get` and `sts get-caller-identity`. The skills never run a mutating verb. | Cloud skills (`generate-cloud-vdr-config`, `update-cloud-vdr-config`) |
| `terraform` | Optional, for formatting and offline validation of Terraform edits; never used to apply infrastructure. | `tag-terraform-vdr-assets` |

`generate-security-objectives` needs no live access to Kubernetes or a cloud
account.

### 2. Install the skills in your agent

#### Claude Code

Claude Code needs **both** commands. Adding the marketplace only registers the
source; the skills are not visible to the agent until the plugin is installed
from it.

```
/plugin marketplace add stackArmor/vdr-agent-skills
/plugin install trivy-plugin-vdr-skills@trivy-plugin-vdr-skills
```

#### Antigravity CLI (AGY)

```bash
agy plugin install https://github.com/stackArmor/vdr-agent-skills
```

Other Antigravity options:

- **Project / workspace auto-discovery:** when running AGY inside this
  repository or any project containing the `.agents/skills/` directory, AGY
  automatically discovers all skills. Confirm discovered skills in chat with
  `/skills`.
- **Manual global plugin:** clone or symlink the repository into your global
  AGY plugins directory:
  ```bash
  # Option A: Clone directly into plugins
  git clone https://github.com/stackArmor/vdr-agent-skills.git ~/.gemini/config/plugins/vdr-agent-skills

  # Option B: Symlink from an existing local clone
  ln -s /path/to/vdr-agent-skills ~/.gemini/config/plugins/vdr-agent-skills
  ```
- **Global skills directory:** copy or symlink the skills into
  `~/.gemini/config/skills/`:
  ```bash
  mkdir -p ~/.gemini/config/skills
  cp -r .agents/skills/* ~/.gemini/config/skills/
  ```

Restart AGY or start a new session, then run `/skills` to verify that the
skills are loaded.

#### OpenAI Codex (CLI and App)

```bash
npx skills add stackArmor/vdr-agent-skills --agent codex
```

Other Codex options:

- **Interactive Skill Installer (Codex CLI):** type `$` to open the action
  menu, select **Skill Installer**, and paste the repository URL:
  ```
  https://github.com/stackArmor/vdr-agent-skills
  ```
- **Project / workspace level:** Codex automatically discovers skills that
  follow the Agent Skills standard in `.agents/skills/` (or `.codex/skills/`)
  at the repository root. When working in this repository, or after copying
  `.agents/skills/` into your target project, the skills are immediately active.
- **Global installation:** copy or symlink the skills into your user-level
  Codex skills directory:
  ```bash
  mkdir -p ~/.codex/skills
  cp -r .agents/skills/* ~/.codex/skills/
  ```

Restart your Codex session after installation so the runtime indexes the new
skills.

#### Gemini and other agents

All skills ship under `.agents/skills/`, following the open Agent Skills
specification (`<skill>/SKILL.md`). Any agent that supports the
`.agents/skills/` directory standard discovers them automatically when
operating in the workspace.

> **Troubleshooting: the clone prompts for a password** and ends with
> `fatal: unable to get password from user`? Check the repository name first.
> GitHub cannot tell a private repository from a missing one without
> authentication, so a mistyped name looks like a credentials problem. It
> usually is not one.

### 3. Run the core skills

Start with the two core skills. Use whichever applies to your environment, or
both:

| Skill | Target | Output | Live access |
|-------|--------|--------|-------------|
| `generate-k8s-vdr-configmap` | Kubernetes workloads | `vdr-fedramp` ConfigMap | `kubectl` |
| `generate-cloud-vdr-config` | AWS, Azure & GCP resources (object storage, VMs, managed SQL, BigQuery, etc.) | `vdr-cloud.yaml` | `aws` / `az` / `gcloud` |

Invoke a skill by name or describe your intent, for example:

- *"Set up the FedRAMP scoring ConfigMap for my cluster"*
- *"Generate the VDR cloud config for my AWS account"*

Then follow this workflow:

1. **Run the skill.** Run `generate-k8s-vdr-configmap` and/or
   `generate-cloud-vdr-config`, depending on what you operate. The agent asks
   you questions and walks you through each step.
2. **Review the output.** Check the generated file for accuracy before
   deploying, with particular focus on any labels the agent marks as **low
   confidence** — the classification drives your remediation deadlines.
3. **Deploy.**
   - **ConfigMap:** apply it to your cluster yourself (`kubectl apply -f`). It
     can live in your GitOps repository alongside your other manifests.
   - **`vdr-cloud.yaml`:** upload it to cloud storage in your environment
     (e.g., S3, Azure Blob Storage, or GCS). This can also be managed through GitOps.

### Azure cloud classification

Use `generate-cloud-vdr-config` with the existing Azure CLI login, explicitly
confirmed subscriptions, and read-only permissions. Azure Commercial and US
Government are supported. Azure scopes use `subscription`, and the same
`vdr-cloud.yaml` covers Azure VM, managed database, storage, network, messaging,
and Container Apps resource families. For coverage maintenance, use
`update-cloud-vdr-config`.

See [Azure inventory and identity rules](skills/generate-cloud-vdr-config/references/azure-inventory.md)
and the [fictional Azure policy](skills/generate-cloud-vdr-config/assets/vdr-cloud.azure.example.yaml).
The helper never changes cloud/account selection, installs extensions, or reads
secret values. Preserve any failed collection warnings and excluded types.

## What the skills produce

The core skills produce two outputs carrying the same classification metadata:

- **Kubernetes workloads** — a `vdr-fedramp` ConfigMap
- **Cloud resources (AWS, Azure & GCP, non-Kubernetes)** — a `vdr-cloud.yaml` file

Both capture your FedRAMP **Certification Class**, **agency scope** (single vs.
multi-agency), and a security-impact profile for each asset, plus a coverage
report flagging anything that needs manual review. This metadata drives PAIN
scoring and `VDR-TFR-PVR` remediation deadlines.

> **Not every asset is classified.** Some assets, such as secrets, KMS keys, and
> IAM accounts and profiles, are **not** included in the output. Security
> impact profiles apply only to resources that impact VDR scoring.

## The skills

Seven skills ship in the repository. **Run the two core skills.** The other
five are available for specific needs but are not part of the standard flow.

### Core skills — run these

| Skill | Target | Output | Live access |
|-------|--------|--------|-------------|
| `generate-k8s-vdr-configmap` | Kubernetes workloads | `vdr-fedramp` ConfigMap | `kubectl` |
| `generate-cloud-vdr-config` | AWS, Azure & GCP resources | `vdr-cloud.yaml` | `aws` / `az` / `gcloud` |

### Also available

| Skill | Target | Output | Live access |
|-------|--------|--------|-------------|
| `generate-security-objectives` | System and agency security objectives, from documentation and the NIST SP 800-60 catalog | Security objectives file with ceiling | None |
| `update-k8s-vdr-configmap` | Updating an existing Kubernetes classification | Updated ConfigMap | `kubectl` |
| `update-cloud-vdr-config` | Updating an existing cloud classification | Updated `vdr-cloud.yaml` | `aws` / `az` / `gcloud` |
| `tag-terraform-vdr-assets` | Terraform-managed assets | Asset tags | See skill |
| `capture-dataflow-beta` (**Beta**) | Data flows | See skill | See skill |

### `generate-k8s-vdr-configmap` → the SIP-based `vdr-fedramp` ConfigMap

Interviews the operator to capture the canonical scoring attestations: the
FedRAMP **Certification Class**, **agency scope** (single/multi-agency), and
per-workload security-impact profiles expressed as direct vectors,
compositional decision traces, or named archetypes. Emits a central
`vdr-fedramp` ConfigMap rule for every workload plus an assignment-coverage
ledger with confidence and manual-review reporting.

### `generate-cloud-vdr-config` → the central `vdr-cloud.yaml`

Extends the central-assignment model to **non-Kubernetes cloud resources**. It
discovers CIS Foundations-addressed GCP, AWS, and Azure resource families (object
storage, VMs, managed SQL, BigQuery datasets, and the rest) with read-only
`gcloud`/`aws`/`az` CLIs, interviews the operator, and emits a single multi-scope
`vdr-cloud.yaml` (`CloudResourceScoringConfig`) plus an inventory baseline and a
coverage ledger. Resources are matched by **name, tag, network, or type rules**
with family-tier precedence, or by whole account/project defaults; each resolves
FedRAMP Class, agency scope, and a CR/IR/AR security-impact profile
independently down the chain. This document is the **primary** assignment
surface, so per-resource `vdr.fedramp.io/*` tags are demoted to
exceptions/overrides. Provider-managed resources (staging buckets, template
stores, CDK assets, ...) are matched against a governed catalog and
**materialized as reviewable medium-confidence rules**, never assumed silently.

For details on the additional skills, see [Additional skill details](#additional-skill-details).

## Security posture: read-only, your credentials

The skills run standard CLI commands through your local `kubectl`, `aws`, `az`, and
`gcloud` installations, using the credentials you already have configured.

- **Read-only verbs only.** The skills and their scripts use only read-only
  verbs (e.g., `kubectl get` / `list`, `gcloud asset list`, `aws ... describe`)
  — never `exec`, `apply`, `label`, `patch`, `delete`, or any other mutating
  verb.
- **No Terraform deployment.** The Terraform skill never reads state or plan
  files and never runs `terraform apply`; it edits only operator-approved HCL
  and validates the resulting diff.
- **Secret values never leave the cluster.** Where Secret-declared
  connections are analyzed, values are reduced to `host:port` endpoints in
  all outputs; credentials are never written to any artifact.
- **Artifacts stay local** until the operator applies them. Every generated
  manifest, config file, and label command is written to a local output
  directory for review; applying or uploading is an explicit operator action
  (`kubectl apply -f`, an upload to S3/GCS, or a GitOps commit).
- Operator attestations remain distinct from agent inferences. Missing impact
  detail does not suppress an objectives artifact, ConfigMap, or cloud config:
  each skill makes a conservative, evidence-backed assessment and exposes its
  confidence and review needs. HA is mitigation evidence and never lowers the
  Availability Requirement.

## How the outputs are consumed

The classification you generate is one input to the PAIN scoring model in
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr), which
combines your assets' security-impact profiles with exploitability, internet
reachability, and multi-agency scope to set FedRAMP remediation deadlines.

- **`vdr-fedramp` ConfigMap** — read in-cluster; drives PAIN scoring and
  `VDR-TFR-PVR` remediation deadlines (Certification Class, agency scope, and
  security-impact-profile rules).
- **`vdr-cloud.yaml`** — uploaded to cloud storage in your environment (e.g.,
  S3 or GCS); carries the same classification metadata for non-Kubernetes
  cloud resources.
- **`securityRequirementsCeiling`** — optional, in the `vdr-fedramp` ConfigMap
  or via the corresponding runtime flag; caps profile CR/IR/AR values only
  when recalculating reported PAIN scores. Its absence is valid and silent.
- **`vdr-dataflow` ConfigMap (Beta)** — can supply experimental dataflow
  evidence for internet-reachability determination, but may be changed or
  deprecated.

For the full methodology, derivations, and design rationale, see the VDR white
papers at
[stackarmor.github.io/rfc-fedramp-vdr](https://stackarmor.github.io/rfc-fedramp-vdr).
See the trivy-plugin-vdr README for the ConfigMap schemas.

## License

MIT — see [LICENSE](LICENSE).

## Additional skill details

### `update-k8s-vdr-configmap` / `update-cloud-vdr-config`

Update an existing Kubernetes or cloud classification, producing an updated
`vdr-fedramp` ConfigMap or `vdr-cloud.yaml` respectively. They use the same
read-only `kubectl` or `aws`/`az`/`gcloud` access as the corresponding generate
skills.

### `generate-security-objectives` → `security-objectives.json`

Assesses the **system's** security objectives (what the product holds and does
by design) together with the deploying **agency's** expected use (the data that
agency will actually place in the system). It applies the FedRAMP Class as a
transparent prior, not as authority over the data profile, and derives an
optional ceiling with `min(SSO, ASO)`. The single JSON artifact contains the
evidence, confidence, divergence record, wire value such as
`cr-m_ir-m_ar-l`, and display value such as `CR:M/IR:M/AR:L`. It does not
access Kubernetes, classify components, or generate a ConfigMap.

The skill includes a
[source-pinned machine-readable catalog](skills/generate-security-objectives/references/nist-sp-800-60-v2r1-information-types.json)
of all 170 information-type records in NIST SP 800-60 Volume II Revision 1. It
queries the catalog to identify candidate FIPS 199 information types, preserves
each record's provisional C/I/A profile and special factors, and records how
confirmed types informed the system and agency objectives. NIST recommendations
remain advisory starting points and never replace actual-use evidence or a
governing categorization.

The ceiling may be copied into `vdr-fedramp` as
`securityRequirementsCeiling` or passed to trivy-plugin-vdr with
`--security-requirements-ceiling`. Using it is optional.

### `tag-terraform-vdr-assets` → selective Terraform metadata

Inventories AWS, Azure, and GCP Terraform and allows only asset families
addressed by the supplied CIS Foundations Benchmarks (for example projects or
accounts, VMs, databases, buckets, logging, and network boundaries). It
separately interviews the operator for compositional CR/IR/AR decision traces,
then adds provider-valid tags or labels only where the pinned provider or
module supports them. Untaggable IAM and control resources are reported as
coverage gaps instead of receiving invalid Terraform arguments. GCP projects
and AWS accounts can optionally carry confirmed Certification Class and
multi-agency defaults.

### `capture-dataflow-beta` → the `vdr-dataflow` ConfigMap (Beta)

> **Beta.** `capture-dataflow-beta` may be deprecated, and its schema should
> not be treated as a stable interface. Treat its generated artifacts as
> experimental analysis aids, and do not build automation that depends on its
> output format.

The skill is useful for discovering and reviewing data flows and
interrelationships among workloads, services, ingress paths, policy controls,
and external dependencies in Kubernetes environments. It builds the cluster's
dataflow evidence for internet-reachability analysis by working through
evidence sources in stages — declared **NetworkPolicies**, then **service-mesh
authorization** resources, then optional **Hubble / mesh flow exports**, then
declared **env / Secret / ConfigMap** connection analysis. It produces the
`vdr-dataflow` ConfigMap plus per-namespace Mermaid diagrams for operator
review. The agent-assisted review also records **broker candidates** — possible
payload paths through cloud brokers (SQS, S3, Pub/Sub, GCS, ...) that Kubernetes
alone cannot confirm — each with the workload-identity principal to verify
against IAM later.

## Development checks

Use a virtual environment and install `tests/requirements.txt`, then run
`python -m unittest discover -s tests`. Runtime discovery remains standard-library
only; the test dependencies cover YAML, optional regex rules, and actual Azure
CLI query projection semantics.
