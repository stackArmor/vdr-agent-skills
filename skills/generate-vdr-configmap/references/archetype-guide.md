# Archetype attestation guide

How to propose an asset archetype for each workload and confirm it with the
operator. The archetype assigns the CR/IR/AR (Confidentiality / Integrity /
Availability Requirement) weights that drive PAIN scoring in trivy-plugin-vdr.

## Certification Class mapping

The Class selects the remediation-deadline column block in the FedRAMP
`VDR-TFR-PVR` matrix. Operators locate themselves by their existing FedRAMP
authorization level:

| FedRAMP authorization | Certification Class |
|-----------------------|---------------------|
| FedRAMP Ready         | A                   |
| FedRAMP Low           | B                   |
| FedRAMP Moderate      | C                   |
| FedRAMP High          | D                   |

Higher classes carry shorter deadlines (Class D is the fastest). The Class
must be confirmed explicitly by the operator — never defaulted.

## The catalog

CR/IR/AR: H = High (1.5), M = Medium (1.0), L = Low (0.5) in the CVSS v3.1
environmental formula. This catalog is the plugin's built-in rubric; a CSP may
override entries via the ConfigMap's embedded `scoring.yaml`, but should own
and justify any change.

| Archetype             | Lens    | CR | IR | AR | Typical members |
|-----------------------|---------|----|----|----|-----------------|
| `cicd-pipeline`       | control | H  | H  | H  | build/deploy runners, artifact signing, registries |
| `orchestrator`        | control | H  | H  | H  | control plane, etcd, scheduler, coordination, CNI/CSI |
| `config-actuation`    | control | H  | H  | H  | IaC/GitOps controllers, schema registry, admin/migration jobs |
| `identity-secrets`    | control | H  | H  | H  | IdP/SSO, KMS, secrets managers, session/token stores |
| `security-tooling`    | control | H  | H  | M  | scanners, SIEM, EDR, runtime security, admission policy |
| `change-record`       | control | M  | M  | M  | ITSM/ticketing (record only) |
| `platform-foundation` | control | L  | H  | H  | DNS, NTP, service discovery, plain L4 internal LBs (metadata only) |
| `data-sensitive`      | data    | H  | H  | H  | PII/CUI datastores |
| `data-backbone`       | data    | H  | H  | H  | payload queues and brokers, the system-of-record DB |
| `telemetry-backbone`  | data    | M  | M  | M  | metrics/trace pipelines, telemetry queues, event buses carrying no agency payload |
| `app-tier`            | data    | M  | M  | M  | stateless services, APIs, UIs, caches |
| `batch-analytics`     | data    | M  | M  | L  | ETL, reporting, analytics jobs |
| `public-edge`         | data    | L  | L  | H  | load balancers, public web, ingress controllers |
| `internal-tooling`    | data    | L  | L  | L  | dashboards, metrics/log agents |
| `dev-test`            | data    | L  | L  | L  | non-production |
| `unclassified`        | —       | H  | H  | H  | fail-safe default for untagged assets |

## The classification rule: control-plane lens first

1. **Control function first.** If the workload can *deploy*, *orchestrate*,
   *hold cross-estate credentials*, or *actuate configuration*, classify it by
   that control function — regardless of the data it stores. A CI runner that
   touches no customer data is still `cicd-pipeline` (H/H/H): it can change
   everything else.
2. **Otherwise, classify by the data it holds.**

The same software lands in different archetypes **by role**, so never
classify by image name alone:

- An in-memory store (Redis, Memcached) is `app-tier` as a cache,
  `identity-secrets` as a session/token store, `data-backbone` as a job
  broker.
- A PostgreSQL instance is `data-backbone` as the system of record,
  `data-sensitive` when it holds PII/CUI, `dev-test` in a staging namespace.
- An nginx pod is `public-edge` as an ingress controller, `app-tier` as an
  internal reverse proxy in front of one service.

When the role is not evident from the namespace, name, and images, **ask the
operator** — the answer is an attestation, not a guess.

### Distinctions that commonly trip people up

- `platform-foundation` is for **metadata-only** foundation services
  (DNS/NTP/discovery/plain L4 LBs): CR is Low because compromise yields
  reconnaissance, not payload. Anything that terminates TLS or sees request
  payload belongs in `app-tier` or `public-edge` instead.
- `data-backbone` vs `telemetry-backbone`: the discriminator is **whether the
  bus carries agency payload data**. Metrics, traces, and heartbeats are
  `telemetry-backbone` (M/M/M); anything moving customer/agency payloads is
  `data-backbone` (H/H/H). Payload data routed through a telemetry bus is a
  misclassification finding — reclassify the bus, don't leave it at Medium.
- `public-edge` keeps AR High while `app-tier` is Medium: a CVE-grade DoS
  hits **every replica at once** (redundancy defends against hardware
  failure, not a flaw shared by the class), and an edge-class outage closes
  the front door for every user, while an app-tier outage degrades one
  service.
- `public-edge` has CR/IR Low because it forwards traffic it does not own;
  its job is availability (AR High). An edge that also performs
  authentication belongs in `identity-secrets` territory — ask.
- `change-record` is the ticket **record** only; a tool that can also
  *actuate* changes (auto-remediation, GitOps sync) is `config-actuation`.
- `security-tooling` sees everything (SIEM) but its own availability loss is
  survivable for a while: AR Medium, not High.

## Resolution order (why both labels and rules exist)

The plugin resolves an archetype most-specific-first:

```
workload label vdr.fedramp.io/asset-archetype
  → namespace label
  → name rule       (ConfigMap scoring.yaml; first match wins)
  → namespace rule  (ConfigMap scoring.yaml; first match wins)
  → built-in "unclassified" cluster default (H/H/H)
```

- **Workloads the customer controls** get the label (via `label-commands.sh`,
  or better, in their Helm charts/manifests).
- **Cloud-managed, shared-responsibility components** (`kube-system`,
  `gke-managed-*`, `amazon-cloudwatch`, `azure-*`, …) cannot carry customer
  labels; they are classified by `nameRules`/`namespaceRules` in the
  ConfigMap. Put specific `nameRules` first (e.g. the workload-identity
  metadata server is `identity-secrets`), then namespace catch-alls
  (`kube-system` leftovers are usually `internal-tooling`).

## The fail-safe is intentional

Anything left unconfirmed stays unlabeled and resolves to `unclassified`
(CR/IR/AR all High), which scores loudly — typically N4 — until classified.
This is by design: "unknown" is treated as serious, and an under-classified
critical asset is a downgrade attack surface. Never propose a quieter default
for a workload the operator has not attested; tell the operator which
workloads remain loud and why.

## Scope flag

`multiAgency` follows the same hierarchy: workload label → namespace label
(`vdr.fedramp.io/multi-agency`) → ConfigMap default. There is no automatic
per-archetype escalation — scope is an explicit operator attestation at each
level.
