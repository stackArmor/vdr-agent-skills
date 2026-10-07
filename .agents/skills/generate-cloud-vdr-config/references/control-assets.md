# Control-asset impact assignments

Classify consequences independently. Requirements are not the actual C/I/A
effects of an SCC finding: a replication finding does not itself disclose a
secret. HA, US-only residency and finding applicability are separate controls.

## Evidence and identifiers

Inventory metadata only through Cloud Asset Inventory RESOURCE and IAM_POLICY.
CAI is eventually consistent (IAM policies can lag); retain that caveat.
Full KMS paths distinguish identically named keys in different rings/regions.
Service accounts use email for rule matching and numeric-ID URI aliases for
SCC joins. Keys use full paths and never include public/private key data.

IAM allow bindings are synthesized as `vdr.fedramp.io/IAMBinding`, not Google's
IAM v3 PolicyBinding. Their ID is SHA256 of the JSON array
`[attachedFullResourceName, member, role, conditionExpression]`, encoded UTF-8,
with separators `(",", ":")` and ASCII escaping. Match exact IDs or narrow
`matchTags` selectors `iam-role`, `iam-member`, `iam-scope`. Conditions are
preserved, not evaluated or assumed to constrain privilege. Attached policies
are not complete inherited/group/deny/PAB or cross-project effective access.
Do not confuse grants on a service account (who may use it) with grants to it.

## Dimensional reasoning

### KMS key-ring grouping

Keep each CryptoKey as a separate inventory/SCC target. Key labels and explicit
name/tag/network/type rules take precedence independently for SIP and multiAgency;
otherwise inherit both resolved values from the owning KeyRing before scope/global
defaults. This is scoring-policy inheritance, not GCP label propagation. Class
and reachability remain independently resolved on the key.

Match the full project/location/keyRing path within the same authorized source,
scope and tenant; allow only verified project ID/number aliases. Never join rings
by short name or across regions. Missing, ambiguous or unresolved rings fail
closed for inherited values. Record the ring identity and its resolution sources
in the key coverage entry. Explicit overrides for both attributes can score a key
independently. Existing explicit key rules remain valid; removing them is a
separately authorized policy migration, not an additive coverage update.

Attest the ring profile to represent the governed keys' data/signing authority,
trusted operations and runtime/recovery dependencies. Use key overrides for
genuine differences; do not score only the ring container's metadata when its
profile is intended to supply its keys' requirements.

### Service-account key grouping

Keep keys as distinct inventory/SCC targets, connected by `authenticates_as`.
Scoring normally comes from the owning service account: explicit key labels
and key name/tag/network/type rules win first; otherwise inherit the owner's
complete SIP before scope/global SIP defaults. Class, multiAgency and
reachability still resolve on the key independently; they are not inherited.

Resolve ownership only by the full IAM path, numeric unique ID or exact email,
inside the same authorized project, source and tenant. Accept verified project
ID/number aliases; never join on a short name. Missing, ambiguous or unresolved
owners fail closed, rather than falling through to a broad default.

CR/IR follow the principal's effective authority, not key rotation age or whether
Google manages the key. AR defaults conservatively to the owner's AR. A genuinely
different credential dependency needs evidence and an explicit key override:
loss of this credential is not necessarily loss of the identity, but alternate
authentication must be verified; HA or automatic rotation alone does not lower AR.
Never treat SYSTEM_MANAGED keys as user-managed downloaded credentials.

If an exception applies to every key for an owner, use one typed, scoped rule:

```yaml
- type: iam.googleapis.com/ServiceAccountKey
  match: "projects/example-project/serviceAccounts/123456789012345678901/keys/*"
  securityImpactProfile: scoped-access.identity-control.operations-support
```

The profile above is illustrative, not a default. Match the owner's established
CR/IR; independently justify the exception's AR. Otherwise omit key rules and
record inherited profile, owner identity and parent resolution source in every
key's coverage entry. Rotation must not create a new scoring gap. Coverage-only
updates preserve existing parent scores and explicit key rules; consolidation
of old rules requires separate operator authorization.

VM images, Artifact Registry repositories and container images are also covered
when they are SCC targets: follow source/content sensitivity, accepted release
authority and recovery dependency. Group identical-role container images with
a repository-scoped full-path glob, not a short image name. Network findings
use the shared connectivity/enforcement foundation. SCC `google.compute.Project`
targets map to the collected Resource Manager project by verified URI/project
aliases, not a second scored copy of the same project.

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| Secret | Contents: identifier/public data L; bounded credential M; broad credentials or signing/session roots H | Consequence of substituted contents: bounded failed login M; trusted config/signature/identity H | Loss of required runtime/recovery credential H; delayed changes or operations M; truly optional L |
| CryptoKey | Protected data or signing authority, not exportability of raw key bytes | Accepted decrypt/sign operations and key lifecycle/authorization | Loss across versions/replicas of protected runtime or recovery; administrative-grant loss is a different dependency |
| KeyRing | When supplying inherited SIP, evaluate protected data/signing authority of the governed keys | Accepted key operations and IAM/lifecycle authority | Governed keys' logical runtime/recovery dependency; container metadata alone is not the inherited impact |
| Service account | Effective accessible data and authority: bounded M; broad secrets/deployment/impersonation H | What its permissions and accessible credentials can alter | Runtime critical path H versus administrative-change delay M |
| SA key | Principal's authority; key material is not read during discovery | Authentication/impersonation consequence | Loss of this credential, considering approved alternate authentication without lowering AR for mere HA |
| Custom IAM role | Permission definition metadata, usually M | Ability to change permissions received by its bound principals, often H | Consequence to dependent principals; unused/deferrable definitions need not be H |
| IAM allow binding | Access capability implied by principal + role + scope | Permitted action, or consequence of tampering with the grant | Revoking this grant, not destroying the underlying resource |
| Project | Governed boundary's data/authority | Shared policy/API/configuration control | Complete logical loss of that project control function |
| Firewall | Network/control metadata, usually M; rule itself does not hold payload | Trusted enforcement H | Whether lost enforcement blocks mandatory protection/shared connectivity |

Use exact governed traces from the archetype guide, preferably over named
archetypes. Examples: runtime shared identity
`privileged-access.config-control.mission-essential`; Terraform state containing
credentials and driving deployments
`privileged-access.config-control.recovery-critical`; nonsecret destination
configuration `public-content.config-control.operations-support`.
These are examples, not family-wide defaults.

Follow consumer references, CMEK edges, safe role permissions and observed
grants. Do not conclude that `cloud-platform` OAuth scope grants administrator
access. A read-only credential can still enable downstream writes through
the credential it retrieves. Lower confidence does not lower requirements;
use the strongest credible consequence and state a concrete review action.

SCC project findings may bundle unrelated grants. Keep the aggregate project
assignment explicit; never claim every bundled binding inherits one profile.
Secret versions and CryptoKey versions normally use their parent asset unless
an independently governed version requires separate treatment. Built-in IAM
role definitions are evidence, not standalone scored assets in this workflow.

Only network-attached assets support network rules. Secrets, KMS, IAM and
projects do not get network attachments or inferred internet-unreachable claims.
Function metadata, images and artifact assets currently have no network attachment
in this collection path; do not author network rules for them.
CAI failure or fallback gaps must be visible and must not produce a claim of
complete control-asset coverage.
