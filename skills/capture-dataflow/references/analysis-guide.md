# Agentic analysis guide — capture-dataflow

The script is deterministic discovery; **you** turn its bundle into a reviewed,
operator-attested dataflow map. Work through every section below with the user after
the first `--emit bundle` run. Do not skip sections — each one exists because the
deterministic pass cannot decide it alone.

Ground rules while analyzing (restate them to the user up front):

- Read-only: you may run `kubectl get`/`kubectl config current-context` to answer
  questions that come up. NEVER `kubectl exec`, NEVER `apply`/`create`/`patch`/
  `delete`, not even `--dry-run=server`.
- Secrets: never print a Secret value into the conversation, a file, or evidence.
  If you must discuss a Secret-derived edge, refer to it by secret name + key only.
- You never apply the ConfigMap. The operator does, after review.

## 1. Stage verdicts — what kind of map do you have?

Read `stages` in `bundle.json`. The question is whether any *enforcement* source
(`networkPolicies`, `meshAuthorization`) is `complete`:

- **complete** — the permitted-flow graph is authoritative; declared-config
  discovery was skipped as a source (unless `--all-stages`). Review is mostly
  confirming exposure and naming.
- **partial** — policies exist but do not cover everything. Tell the user exactly
  what is uncovered (the coverage string counts it; the bundle's per-workload list
  shows `hasEdges`/`exposed`). Uncovered workloads are default-allow.
- **absent** — no enforcement at all. The edges you have are *discovered behavior*,
  not permissions. Say this plainly: "nothing in the cluster restricts east-west
  traffic; this map documents what the config declares, and trivy-plugin-vdr will
  treat the cluster as default-allow unless you attest the topology is complete."

Never present a partial/absent map as if missing edges meant isolation.

## 2. Exposure review

Walk `exposedWorkloads` with the user:

- Does every entry match their expectation of what is internet-facing? A surprise
  entry is a finding in itself — surface it prominently.
- Anything they expected to see but don't? Check for internal-LB annotations or
  internal ingress classes (the script excludes those) and for edge resources in
  namespaces outside the scan scope. Re-run with a wider `--namespaces` if needed.
- Confirm `publicHosts` are truly public DNS names (not split-horizon internal
  names). If a "public" host is actually internal-only, hairpin edges through it are
  misclassified — note it and handle in section 6.

## 3. Zero-edge workloads (image-baked config)

The bundle lists workloads with `hasEdges: false` (also in stage 4 notes). For each
one, its dependencies are probably baked into the image or fetched at runtime —
invisible to the API server. Ask the user a *targeted* question per workload, e.g.:

> "cronjob `webapp/db-backup` has no discoverable dependencies in its env, mounted
> ConfigMaps, or args. What does it connect to? (e.g. 'it streams WAL from
> postgres-rw:5432')"

Capture each answer as an edge in `operator-edges.yaml` with evidence like
`"operator: <their words>"`. A workload the user says talks to nothing (pure batch
on a mounted volume, exporter scraped by Prometheus, ...) needs no edge — record
that in the attestation note instead so the review is auditable.

## 4. Unresolved hosts

For every entry in `unresolved`, triage with the user into exactly one bucket:

| Bucket | Action |
|---|---|
| Service in an unscanned namespace | re-run with that namespace included, or add a `resolveUnresolved` mapping |
| In-cluster service under a different name (CNAME, ExternalName, kube-dns stub) | `resolveUnresolved` mapping to the real Service |
| Cluster-external managed infra (CloudSQL, RDS, ElastiCache, ...) | `external: true` with a note naming the system |
| Vendor SaaS / third-party API | `external: true` with a note |
| Typo / dead config | note it; suggest the user clean it up; `external: true` with note "dead config" so it stops resurfacing |

Do not guess. If the user does not know a host, leave it unresolved — an unresolved
entry in the final ConfigMap is honest and visible; a guessed edge is neither.

## 5. Broker candidates (queues, buckets, topics)

A dataflow through a cloud broker — SQS/SNS, S3, Pub/Sub, GCS, Service Bus, Event
Hubs, managed Kafka — never shows up as a cluster edge: producer and consumer both
dial *out* to a cloud endpoint, and the link between them lives in IAM, not in
Kubernetes. Verifying IAM is out of scope here (it needs cloud APIs). Your job is to
surface *candidates* precisely enough that they can be verified or excluded later.

1. **Spot broker references.** Scan `unresolved` entries, `external`-confirmed
   hosts, and env var names (especially on zero-edge workloads from section 3) for
   broker shapes: `sqs.<region>.amazonaws.com` queue URLs, S3 bucket hosts,
   `pubsub.googleapis.com` plus topic env vars, `storage.googleapis.com`,
   `*.servicebus.windows.net`, `*.blob.core.windows.net`, Kafka bootstrap strings
   pointing outside the cluster, and names like `*_QUEUE_URL`, `*_BUCKET`,
   `*_TOPIC`.
2. **Group by resource.** Extract the concrete resource (queue URL, bucket name,
   topic) and group the workloads referencing it. Two or more referrers is a
   candidate. A *single* referrer still is one when the other side may sit outside
   the cluster — users uploading to a bucket via presigned URLs, a lambda producer,
   another cluster. Flag candidates prominently when any referrer appears in
   `exposedWorkloads`: that is the internet-tainted-producer shape.
3. **Compile the identity.** For each referring workload, find its ServiceAccount
   (`kubectl get deploy/... -o yaml` → `spec.serviceAccountName`, then
   `kubectl get sa <name> -o yaml` — read-only, allowed) and record the principal
   the broker's access policy would name:
   - **GKE Workload Identity Federation:** compile
     `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/PROJECT_ID.svc.id.goog/subject/ns/<namespace>/sa/<ksa>`
     from the *Kubernetes* ServiceAccount. `PROJECT_ID` can usually be read off a
     GKE context name (`gke_<project-id>_<location>_<cluster>`); ask the user for
     `PROJECT_NUMBER` — it is not visible from inside the cluster. If the legacy
     `iam.gke.io/gcp-service-account` annotation is present, note the linked GSA
     too: older grants may target the GSA rather than the federated principal.
   - **EKS:** the role ARN from the KSA's `eks.amazonaws.com/role-arn` annotation
     (IRSA). No annotation may mean EKS Pod Identity, whose associations are not
     visible in-cluster — record `identity: "unknown (check EKS pod-identity
     associations for <ns>/<ksa>)"`.
   - **AKS:** the client ID from `azure.workload.identity/client-id`.
4. **Record the candidate** in `operator-edges.yaml` under `brokerCandidates`
   (format: `references/configmap-schema.md`), with `verify` phrased as the exact
   IAM question — e.g. "which role holds `sqs:SendMessage` vs `sqs:ReceiveMessage`
   on ingest-queue", "who holds `s3:PutObject` vs `s3:GetObject` on
   uploads-bucket", "`roles/pubsub.publisher` vs `roles/pubsub.subscriber` on
   topic ingest".
5. **Ask the user** whether they can verify now, out-of-band. If IAM confirms a
   producer/consumer pair, add the payload edge to `edges` as **producer →
   consumer** (broker named in the evidence, e.g. `"operator: thumbnailer receives
   from ingest-queue written by frontend; IAM verified 2026-07-02"`) and set the
   candidate `status: confirmed`. If IAM rules it out, set `status: excluded` with
   a note naming what was checked. If they cannot verify yet, leave `unverified` —
   the ConfigMap carries it forward honestly.

Never treat an unverified candidate as an edge in either direction: it must not
taint anything and must not justify pruning anything. And keep the payload direction
straight when confirming — the workload that *reads* from the broker is the one
receiving the data, even though it initiated the connection.

## 6. Hairpin edges (`internetTransit: true`)

Configured URLs that point at the cluster's own public hostname resolve to the
routed backend(s) and are marked `internetTransit`. Review them because:

- **Pathless base URLs fan out.** A bare `https://portal.example.gov` fans out to
  every backend routed under that host (conservative). Ask which backend(s) the
  consumer actually calls and replace the fan-out with precise `operator-edges.yaml`
  entries if the user knows; keep the fan-out if they don't.
- **Self-loops are real.** A workload configured with its own public URL genuinely
  round-trips through the edge; keep the edge.
- **Split-horizon DNS.** If the "public" hostname actually resolves in-cluster to an
  internal address (hairpin NAT is bypassed), the payload may not transit the
  internet — but it still enters through the edge-routed path. Default: keep
  `internetTransit: true` unless the user demonstrates the name is internal-only
  (then it belongs in section 2's misclassification handling).

## 7. Scope sanity

- Cross-namespace edges pointing into namespaces you did not scan mean the map has a
  blind side; recommend widening `--namespaces`.
- If the user runs namespace-scoped scans for RBAC reasons, note in the attestation
  that completeness is claimed only for the scanned scope.

## 8. Attestation

Ask the user explicitly, after sections 2-7 are resolved:

> "Can you attest that every inter-workload payload path in <scope> is now
> represented in this map (declaredTopologyComplete: true)? If not, that is fine —
> trivy-plugin-vdr will conservatively treat the topology as default-allow."

Record their answer, name, and date in the `attestation` block of
`operator-edges.yaml`. Never set `true` on their behalf, and never pressure toward
`true` — a false completeness claim creates false NIRV negatives downstream, which
is the exact failure mode this tooling exists to prevent.

## 9. Finalize and iterate

1. Write `operator-edges.yaml` (format: `references/configmap-schema.md`).
2. Re-run with `--merge operator-edges.yaml --emit all`.
3. Present each `diagrams/<namespace>.mmd` to the user (render if the environment
   can; otherwise paste the Mermaid source into a fenced `mermaid` block).
4. If the user corrects an edge, update `operator-edges.yaml` and re-run — never
   hand-edit `configmap.yaml`, it must stay reproducible from script inputs.
5. Hand off: "review `vdr-dataflow-output/configmap.yaml`, then
   `kubectl apply -f vdr-dataflow-output/configmap.yaml` or commit it to your GitOps
   repo." You do not apply it.
