# Managed-resource pattern catalog

Some cloud resources are created and named by a managing service rather than by
the tenant: staging buckets for source archives, template stores, query-result
buckets, CDK bootstrap assets. The tenant has limited control over their naming
and tagging, so they should not consume interview questions meant for resources
humans actually design.

The machine-readable catalog is
[`managed-resource-patterns.json`](managed-resource-patterns.json); this guide
is its prose companion, mirroring how `cis-asset-map.json` and
`cis-asset-map.md` relate. `inventory_cloud_resources.py` loads the JSON and
annotates each matched resource with the pattern id in `builtinPatterns`.

## How a match is used

When discovery matches a pattern, the skill **materializes an explicit rule**
in the scope's `nameRules` (name-glob patterns) or `tagRules` (marker-tag
patterns), carrying a `# builtin-pattern: <id>` comment. Nothing from the
catalog is ever silently assumed:

- The rule is **capped at medium confidence** (`maxConfidence: "medium"`),
  because a name or marker-tag match is an inference about the resource's role,
  not an operator attestation. Per repo convention, medium confidence forces a
  manual-review comment.
- An **unmatched pattern emits nothing** — no speculative rules.
- The operator reviews pattern rules in the same review table as every other
  rule, and may **attest down** by replacing the default trace with a direct
  vector after verifying the staged contents.

### The default trace

Every entry pins the same governed decision trace:

```
service-content.disposable-state.deferrable-work  ->  M / L / L
```

- **CR:M** (`service-content`) is a deliberate **failsafe**: staged source
  archives and templates can embed sensitive material (secrets in code,
  credentials in templates), so the confidentiality requirement is held at
  medium until an operator verifies the contents are non-sensitive and attests
  down.
- **IR:L** (`disposable-state`): contents are deploy-time inputs that later
  deployments overwrite, so integrity tampering has limited standing effect.
- **AR:L** (`deferrable-work`): an outage of the staging store defers
  deployments without degrading running services.

### The standing manual-review note

Every entry carries the shared review pair:

1. attest CR down with a direct vector only after verifying staged contents
   embed no credentials or sensitive material;
2. confirm nothing re-consumes these artifacts after deployment (re-consumption
   would raise IR).

The marker-tag CloudFormation entry adds a leading note that the owning stack,
not this default, defines the resource's real role.

---

## GCP patterns

### `gcp-cloudfunctions-staging`

- **Type:** `storage.googleapis.com/Bucket`
- **Name globs:** `gcf-sources-*`, `gcf-v2-sources-*`
- **Managed by:** Cloud Functions. The service auto-creates these buckets to
  stage function source archives, so its deploy pipeline owns the naming and
  tagging rather than the tenant.

### `gcp-cloudbuild-artifacts`

- **Type:** `storage.googleapis.com/Bucket`
- **Name globs:** `*_cloudbuild`
- **Managed by:** Cloud Build. The service auto-creates this bucket to hold
  build artifacts and logs, so it controls the lifecycle and tenant tagging is
  limited.

### `gcp-cloudrun-sources`

- **Type:** `storage.googleapis.com/Bucket`
- **Name globs:** `run-sources-*`
- **Managed by:** Cloud Run. The service auto-creates these buckets to stage
  source uploads for source-based deployments, so it owns naming and tenant
  tagging is limited.

### `gcp-dataproc-staging`

- **Type:** `storage.googleapis.com/Bucket`
- **Name globs:** `dataproc-staging-*`, `dataproc-temp-*`
- **Managed by:** Dataproc. The service auto-creates these staging and temp
  buckets for cluster job scratch data, so it controls the lifecycle and tenant
  tagging is limited.

### `gcp-container-registry-artifacts`

- **Type:** `storage.googleapis.com/Bucket`
- **Name globs:** `artifacts.*.appspot.com`
- **Managed by:** Container Registry. The service auto-creates this backing
  bucket to store pushed container image layers, so it owns the naming and
  tenant tagging is limited.

### `gcp-appengine-staging`

- **Type:** `storage.googleapis.com/Bucket`
- **Name globs:** `staging.*.appspot.com`
- **Managed by:** App Engine. The service auto-creates this staging bucket to
  stage application deployment artifacts, so it controls the lifecycle and
  tenant tagging is limited.

### `gcp-managed-by-label`

- **Type:** `storage.googleapis.com/Bucket`
- **Marker tags:** `goog-managed-by: *`
- **Managed by:** a GCP service, per the label value. The service auto-applies
  the `goog-managed-by` label to buckets it provisions on the tenant's behalf,
  so that service owns the resource and tenant tagging is limited. This is the
  catch-all for provider-managed buckets a name glob does not name explicitly.

---

## AWS patterns

### `aws-cloudformation-templates`

- **Type:** `AWS::S3::Bucket`
- **Name globs:** `cf-templates-*`
- **Managed by:** CloudFormation. The service auto-creates this bucket to store
  uploaded stack templates, so it owns the naming and tenant tagging is limited.

### `aws-cdk-assets`

- **Type:** `AWS::S3::Bucket`
- **Name globs:** `cdk-*-assets-*`
- **Managed by:** AWS CDK bootstrap. Bootstrap auto-creates this bucket to
  stage synthesized deployment assets, so the bootstrap process owns the naming
  and tenant tagging is limited.

### `aws-elasticbeanstalk-artifacts`

- **Type:** `AWS::S3::Bucket`
- **Name globs:** `elasticbeanstalk-*`
- **Managed by:** Elastic Beanstalk. The service auto-creates this bucket to
  store application version artifacts and logs, so it owns the naming and tenant
  tagging is limited.

### `aws-athena-query-results`

- **Type:** `AWS::S3::Bucket`
- **Name globs:** `aws-athena-query-results-*`
- **Managed by:** Athena. The service auto-creates this bucket to store query
  result output, so it owns the naming and tenant tagging is limited.

### `aws-cloudformation-managed`

- **Type:** `*` (any resource type)
- **Marker tags:** `aws:cloudformation:stack-name: *`
- **Managed by:** CloudFormation. The service auto-applies the
  `aws:cloudformation:stack-name` tag to every resource it provisions, so the
  owning stack controls the resource and tenant tagging is limited. Because
  this spans all types, its first manual-review note reminds the operator that
  the owning stack's purpose — not the disposable-artifact default — defines the
  resource's real role; classify accordingly rather than accepting the default.
