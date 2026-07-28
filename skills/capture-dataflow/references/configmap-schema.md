# vdr-dataflow ConfigMap schema (v1alpha1)

Schema for the ConfigMap emitted by `capture_dataflow.py` and consumed by
[trivy-plugin-vdr](https://github.com/stackArmor/trivy-plugin-vdr) as declared /
operator-attested dataflow topology.

> **Draft status.** `v1alpha1` is a draft pending the trivy-plugin-vdr Phase B
> (transitive payload exposure) implementation. It maps onto the *declared topology*
> (tier-3) and *operator-declared* evidence concepts in that repo's
> `docs/reachability-v2-spec.md`. Field names may change before `v1`; the generator
> pins `schemaVersion` so consumers can reject documents they do not understand.

## Envelope

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vdr-dataflow            # fixed
  namespace: fedramp-vdr-trivy  # fixed; same namespace as other vdr ConfigMaps
data:
  dataflow.yaml: |              # single key; the entire document below
    ...
```

## `dataflow.yaml` document

| Field | Type | Meaning |
|---|---|---|
| `schemaVersion` | string | `v1alpha1` |
| `generated` | string | RFC3339 UTC timestamp of the capture run |
| `generator` | string | tool + version that produced the document |
| `sources` | list | which signal sources contributed, with sufficiency verdicts (below) |
| `attestation` | object | operator attestation of declared-topology completeness (below) |
| `exposedWorkloads` | list | internet-exposed workloads and how they are exposed (below) |
| `edges` | list | directed dataflow edges, payload direction (below) |
| `unresolved` | list | hosts referenced in configuration that could not be mapped (below) |
| `brokerCandidates` | list | possible dataflow links through cloud brokers (SQS, S3, Pub/Sub, ...) pending out-of-band IAM verification (below) |

### `sources[]`

```yaml
sources:
  - type: networkPolicy          # networkPolicy | meshAuthorization | observedFlows |
                                 # declaredConfig | operatorDeclared
    verdict: partial             # complete | partial | absent
    coverage: "12/14 workloads selected by >=1 policy; default-deny(ingress) namespaces: 1/3"
```

Verdict semantics per source type:

- `networkPolicy` — **complete** iff every in-scope workload is selected by at least
  one policy AND every in-scope namespace has a default-deny ingress policy (so the
  explicit allows fully define the permitted-flow graph). Otherwise partial/absent.
  This is the only source type whose edges are *enforced* permissions.
- `meshAuthorization` — same shape, evaluated over mesh-enrolled workloads and
  authorization policies (Istio `AuthorizationPolicy`, Linkerd `Server`/
  `ServerAuthorization`). **complete** requires full enrollment, full authorization
  coverage, and a default-deny posture.
- `observedFlows` — can never be `complete`: observation proves presence, never
  absence. Observed flows only ever **add** edges or enrich existing ones.
- `declaredConfig` — can never be `complete`: configuration baked into container
  images is invisible to the API server. At best `partial`.
- `operatorDeclared` — `complete` iff `attestation.declaredTopologyComplete: true`,
  else `partial`.

**Consumer rule (default-allow):** unless at least one source has
`verdict: complete` (or the operator attests completeness), the *absence* of an edge
between two workloads MUST NOT be read as isolation. The consumer should treat
topology as default-allow, exactly as trivy-plugin-vdr Phase B specifies
(no data => T(a)=true).

### `attestation`

```yaml
attestation:
  declaredTopologyComplete: true      # operator's claim, not the tool's
  attestedBy: "ops@example.gov"
  date: "2026-07-01"
  note: "reviewed with platform team; backup cronjob edge added manually"
```

`declaredTopologyComplete: true` means the operator asserts every inter-workload
payload path in the scanned scope is represented in `edges`. It is supplied only via
the `--merge` operator-edges file (see below); the generator never sets it on its own.

### `exposedWorkloads[]`

```yaml
exposedWorkloads:
  - namespace: webapp
    kind: deployment              # deployment | statefulset | daemonset | cronjob
    name: frontend
    via:
      - "ingress/webapp/frontend (class gce)"
      - "httproute/webapp/frontend-route -> gateway webapp/external-gw (class gke-l7-regional-external-managed)"
    publicHosts:
      - portal.agency.example.gov
```

A workload appears here when an Ingress rule, Gateway API HTTPRoute, or Service of
`type: LoadBalancer` routes to it and the edge resource is not detectably internal
(internal LB annotations and `*internal*`/`*rilb*` classes are excluded).

### `edges[]`

```yaml
edges:
  - from:
      namespace: webapp
      kind: deployment
      name: reports-api
    to:
      namespace: webapp
      service: postgres-rw        # the Service fronting the destination
      port: 5432                  # int, or a named port string; omitted if unknown
      protocol: postgres          # scheme/port-derived hint; "tcp" when unknown
    sources:                      # every source that asserted this edge
      - declaredConfig
      - observedFlows
    evidence:                     # capped at 8 entries per edge
      - "env:DATABASE_URL<-secret/db-creds:url (value redacted; scheme+host+port only)"
      - "flow:hubble 2026-07-01T12:00:00Z"
    internetTransit: false
```

Semantics:

- **Direction is payload direction**: `from` initiates a connection that delivers
  data to `to`. This feeds taint propagation (internet-tainted `from` taints `to`).
- `to` is always a Service. Edges derived from pod-selecting policies are mapped to
  the Service(s) selecting the destination workload; destination workloads fronted
  by no Service cannot be expressed in `v1alpha1` (recorded in the bundle's stage
  notes instead).
- `internetTransit: true` marks a **hairpin** edge: the configured host is one of the
  cluster's own public hostnames, so the payload leaves the cluster and re-enters
  through the internet-facing edge. These edges keep the destination
  internet-relevant even if it has no direct exposure of its own. When the
  configured URL carries a path, routing path-prefix matching narrows the hairpin to
  the actually-routed backend(s); pathless base URLs conservatively fan out to every
  backend routed under that host.
- **Secret redaction guarantee:** evidence strings name the env var / ConfigMap key /
  Secret key an edge was derived from, never values. From Secret-sourced text only
  scheme, host, and port are ever extracted; URL paths from Secrets are not even
  used for hairpin narrowing.

### `unresolved[]`

```yaml
unresolved:
  - host: search-index            # host referenced in config, mapped to no Service
    usedBy:
      - webapp/deployment/reports-api
  - host: api.vendor-saas.com
    usedBy:
      - webapp/deployment/worker
    note: "operator-confirmed external destination"   # set via --merge resolveUnresolved
```

Unresolved hosts are recorded, never guessed. They require operator triage (see
`analysis-guide.md`): external SaaS, a Service in an unscanned namespace, a typo, or
cluster-external infrastructure (CloudSQL, RDS, ...).

### `brokerCandidates[]`

A dataflow that runs through a cloud broker — SQS/SNS, S3, Pub/Sub, GCS, Service
Bus/Event Hubs, managed Kafka — is invisible to the cluster: producer and consumer
each make an *outbound* connection to a cloud endpoint, and the payload path between
them exists only in the broker's access policy. Kubernetes data alone can never
confirm it. A candidate records that workloads reference the same broker resource,
plus the cloud identity each workload runs as, so the link can be verified — or
excluded — later against IAM.

```yaml
brokerCandidates:
  - broker: sqs                   # sqs | sns | s3 | pubsub | gcs | servicebus | eventhub | kafka | other
    resource: "https://sqs.us-east-1.amazonaws.com/123456789012/ingest-queue"
    referencedBy:
      - workload: webapp/deployment/frontend
        serviceAccount: webapp/frontend
        identity: "arn:aws:iam::123456789012:role/frontend-irsa"
        evidence: ["env:UPLOAD_QUEUE_URL"]
      - workload: webapp/deployment/thumbnailer
        serviceAccount: webapp/thumbnailer
        identity: "arn:aws:iam::123456789012:role/thumbnailer-irsa"
        evidence: ["env:QUEUE_URL"]
    verify: "which role holds sqs:SendMessage vs sqs:ReceiveMessage on ingest-queue"
    status: unverified            # unverified | confirmed | excluded
    note: "frontend is internet-exposed; if thumbnailer receives from this queue it is payload-exposed"
```

Semantics:

- **Candidates are not edges.** The consumer (trivy-plugin-vdr) MUST ignore them for
  taint propagation. They are a verification work queue — surfaced as analysis
  warnings, nothing more. An unverified candidate never taints anything, and never
  prunes anything.
- **`identity` is the principal to look up in the broker's access policy**, in the
  form that policy actually uses:
  - **GKE Workload Identity Federation** — the compiled principal built from the
    *Kubernetes* ServiceAccount (not the `iam.gke.io/gcp-service-account`
    annotation):
    `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/subject/ns/<namespace>/sa/<ksa>`.
    If the legacy annotation is present, record the linked GSA in `note` as well —
    older grants may target the GSA instead of the federated principal.
  - **EKS IRSA** — the role ARN from the KSA's `eks.amazonaws.com/role-arn`
    annotation. EKS Pod Identity associations are not visible from inside the
    cluster; when no IRSA annotation exists, record
    `identity: "unknown (check EKS pod-identity associations for <ns>/<ksa>)"`.
  - **AKS workload identity** — the client ID from the KSA's
    `azure.workload.identity/client-id` annotation.
- **Confirmed** (IAM shows one side can write and the other can read): the payload
  edge is added to `edges` via `operator-edges.yaml` as **producer → consumer**
  directly, with the broker named in the evidence string. Recording the edge this
  way captures the *payload* direction taint propagation needs; the two TCP
  connections (both outbound to the cloud) are irrelevant. Set the candidate's
  `status: confirmed` so the review is auditable.
- **Excluded** (IAM shows no producer/consumer pair): keep the candidate with
  `status: excluded` and a note naming what was checked, so it stops resurfacing on
  the next capture run.

## `operator-edges.yaml` (input to `--merge`)

The agent-assisted review captures operator knowledge in this file; the script merges
it with source `operatorDeclared`:

```yaml
attestation:
  declaredTopologyComplete: true
  attestedBy: "ops@example.gov"
  date: "2026-07-01"
  note: "reviewed with platform team"
edges:
  - from: {namespace: webapp, kind: cronjob, name: db-backup}
    to: {namespace: webapp, service: postgres-rw, port: 5432, protocol: postgres}
    evidence: ["operator: backup job streams WAL from postgres-rw"]
    # internetTransit: true      # optional, defaults false
suppressEdges:
  - from: {namespace: webapp, kind: deployment, name: worker}
    internetTransit: true
    reason: "configured public base URL constructs links; it does not initiate payload calls"
resolveUnresolved:
  - host: search-index           # map an unresolved host to a real Service...
    to: {namespace: search, service: elasticsearch, port: 9200}
  - host: api.vendor-saas.com    # ...or confirm it as external
    external: true
    note: "vendor SaaS, data leaves the cluster"
brokerCandidates:                # passed through verbatim into the ConfigMap
  - broker: sqs
    resource: "https://sqs.us-east-1.amazonaws.com/123456789012/ingest-queue"
    referencedBy:
      - workload: webapp/deployment/frontend
        serviceAccount: webapp/frontend
        identity: "arn:aws:iam::123456789012:role/frontend-irsa"
        evidence: ["env:UPLOAD_QUEUE_URL"]
      - workload: webapp/deployment/thumbnailer
        serviceAccount: webapp/thumbnailer
        identity: "arn:aws:iam::123456789012:role/thumbnailer-irsa"
        evidence: ["env:QUEUE_URL"]
    verify: "which role holds sqs:SendMessage vs sqs:ReceiveMessage on ingest-queue"
    status: unverified
```

`suppressEdges` removes discovered edges that the operator rejects during review.
Suppressions run before `edges` are added, so they cannot remove an
operator-declared edge from the same merge file. Every suppression requires:

- an exact `from` workload (`namespace`, `kind`, and `name`);
- a non-empty `reason`; and
- at least one narrowing selector: exact/partial `to`, boolean
  `internetTransit`, exact `source`, or an `evidenceContains` substring.

The optional `to` selector requires `namespace` and `service`; `port` and
`protocol` further narrow it. Invalid suppression rules stop generation instead of
silently producing an inaccurate map. Rules that match no edge produce a warning.

Plain YAML subset: block mappings/sequences, inline `{}`/`[]` flow values, quoted
scalars, `#` comments. No anchors, no multi-line block scalars (PyYAML is used when
available; the built-in fallback parser accepts exactly this subset).

## Consumption by trivy-plugin-vdr (Phase B)

- `edges` provide tier-3 *declared topology* edges; `sources`/`verdict` tell the
  plugin whether policy-based pruning is sound (`networkPolicy: complete`) or the
  no-data conservative default applies.
- `exposedWorkloads` corroborates (never replaces) the plugin's own Phase A direct
  exposure analysis.
- `internetTransit` edges are internet-tainted regardless of upstream workload taint.
- `operatorDeclared` edges and the attestation map onto the operator-declared
  evidence class; `unresolved` entries surface as analysis warnings.
- `brokerCandidates` are ignored for taint propagation and pruning alike; they
  surface as analysis warnings until verified. A confirmed candidate arrives as a
  regular producer → consumer edge, not as a candidate.
