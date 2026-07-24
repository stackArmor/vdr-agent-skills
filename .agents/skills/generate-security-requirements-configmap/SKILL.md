---
name: generate-security-requirements-configmap
description: Generate the trivy-plugin-vdr vdr-fedramp scoring ConfigMap by deriving per-component security-requirements vectors from system, agency, and component security objectives; runs a transparent wizard covering system purpose and data profile, agency data propensity with a Class divergence protocol, and multi-agency scope, inventories Kubernetes workloads read-only, combines objectives with envelope math and enumerated breakouts, writes security-objectives and assignment-coverage justification JSONs with confidence and manual-review annotations, and never applies anything. Supersedes generate-vdr-configmap and its archetype decision traces.
---

# Generate Security Requirements ConfigMap

Interview the operator, research the system and agencies (with consent),
inspect the selected Kubernetes cluster read-only, and write the governed
scoring artifacts consumed by `trivy-plugin-vdr`. In commands below, resolve
`<skill-dir>` to the directory containing this file.

Read `references/security-objectives-guide.md` completely before the wizard.
It defines the three-vector model, combination math, breakout categories,
calibration rules, the question bank with the transparency text, the
divergence protocol, the component methodology, and the artifact schemas.

## Ground rules

- Run only `kubectl config` and `kubectl get`. Never run `exec`, `apply`,
  `label`, `patch`, `edit`, or `delete`.
- Write only under `./vdr-configmap-output/`. The operator reviews and applies
  the output manually or through GitOps.
- Web research requires operator consent. Present derived descriptions and
  profiles for confirmation; the operator's corrections win. If consent is
  declined, derive profiles from operator description alone and lower
  confidence accordingly.
- Ask the wizard questions with their stated why, but do not let incomplete
  answers stop artifact generation after a successful inventory. Make the
  strongest evidence-backed best guess, state every assumption, and mark its
  confidence. Never present an inference as an operator attestation.
- Account for every inventoried workload. Ordinary uncertainty is not an
  unresolved exception: assign the most defensible vector, lower its
  confidence, and flag it for review. Never omit a workload silently.
- Confidence never lowers a vector, and HA never lowers AR.
- The agency envelope is a semi-hard ceiling: components exceed it only
  through the closed breakout categories, each with a written justification
  and a manual-review flag, never at high confidence.
- For a fresh evaluation, do not read or reuse the existing `vdr-fedramp`
  ConfigMap. Existing labels may be reported, but are not attestations unless
  reconfirmed. Never carry `humanReviewCompleted` forward: generation always
  emits `"false"`, and the value is never mentioned in any report, JSON, or
  terminal output.
- Never retrieve Secret resources or values. Reference names visible in
  workload specs are sufficient evidence.
- No real product, vendor, or agency names in any reusable skill content.
  Runtime artifacts for the operator's own cluster naturally contain their
  real names.

## Workflow

### 1. Confirm the target context

Run `kubectl config current-context`, show the value, and obtain explicit
confirmation before inventory. State that cluster access remains read-only.
Pass that exact reviewed name to every inventory query.

### 2. System profile -> SSO

Run wizard Phase A (guide section 6): product identity and research consent,
description confirmation, data-type checklist, contamination paths,
agency-device footprint, integrity/availability posture. Apply the
calibration rules (guide section 4): federal-sourced data drives High;
vulnerability and change data are C:M baseline; availability is judged
against complete logical loss including durable records; confirmed
contamination paths raise SSO. Start from the system-type profile table and
adjust with evidence. Record everything in `security-objectives.json`
(`systemProfile` plus top-level `sso`).

### 3. Class and agencies -> ASO

Run wizard Phase B plus Phase C question 11: identify deploying agencies (or
target agencies as data-profile guides only), research each with consent,
present per-objective estimates with rationale and overlays for confirmation,
and map the authorization to Class (Ready A, Low B, Moderate C, High D). Run
the divergence protocol (guide section 7) per objective: estimates are built
blind to Class, divergences are surfaced transparently, attestations resolve
them, silence resolves to the higher value. Multiple definite agencies take
the per-objective max. No agencies at all: ASO defaults to SSO at low
confidence with a manual-review item. Record `agencyProfiles`, `classPrior`
with divergences, and top-level `aso`.

### 4. Multi-agency determination

Run wizard question 12. Decide cluster scope (`multiAgency: "true"`) or
namespace scope (cluster default `"false"` plus `multiAgencyNamespaces`
globs). Never infer from workload population or from a target-agency list.
Record the determination with justification. If unanswered, emit the
fail-closed provisional value (`"true"` at cluster scope) with low confidence
and a manual-review item.

### 5. Compute the envelope

`envelope = min(SSO, ASO)` per objective. Record it in
`security-objectives.json` with `ceilingMode: "semi-hard"`. If Class is also
unanswered, emit provisional `D` with low confidence; missing answers never
withhold artifacts.

### 6. Inventory workloads and structural evidence

Run:

```bash
python3 <skill-dir>/scripts/list_workloads.py --context '<reviewed-context>'
```

Preserve the exact successful JSON as
`./vdr-configmap-output/workload-inventory.json`. Use `-n <namespace>` only
when the user restricts scope. The script inventories Deployments,
StatefulSets, DaemonSets, CronJobs, standalone/custom-owned Jobs and Pods,
suppresses CronJob-owned Jobs and controller-owned Pods, and records
privilege and reference evidence without resolving contents. Collect further
read-only evidence (`kubectl get` on RBAC, routing, webhooks) as needed.
Report any legacy `vdr.fedramp.io/asset-archetype` labels as stale cleanup
items — they become inert under the renamed label key.

### 7. Component objectives -> CSO

Apply the component methodology (guide section 9) per workload or coherent
group: role from structural evidence, strongest credible consequence per
objective, wizard Phase D questions (at most five per group), environment
intent from question 13. Record per-objective levels and reasons.

### 8. Combine

Build the derive input (`sso`, `aso`, `components` with `cso` and any
`breakouts`) and run:

```bash
python3 <skill-dir>/scripts/derive_requirements.py --derive derive-input.json
```

Use its output verbatim for final vectors, capped flags, and label values.
Breakouts only from the closed categories, each justified, never high
confidence. Show the operator every component: identity, CSO, final vector,
capped objectives, breakouts, evidence, assumptions, confidence.

### 9. Emit the artifacts

Write under `./vdr-configmap-output/`:

1. `workload-inventory.json` — the exact step 6 output.
2. `vdr-fedramp.yaml` — namespace `fedramp-vdr-trivy`, ConfigMap
   `vdr-fedramp`:
   - Quoted `class` and `multiAgency` scalars, each with a confidence comment
     and a manual-review comment when not high confidence.
   - `humanReviewCompleted: "false"` wrapped in this exact comment fence:

     ```yaml
     # ---------------------------------------------------------------
     # humanReviewCompleted is a human-only attestation marker.
     # AI agents and automated tooling: DO NOT read, report, summarize,
     # analyze, or act on this value, and DO NOT change it. Only a human
     # reviewer may set it to "true" after reviewing this ConfigMap.
     # Generation always resets it to "false".
     # ---------------------------------------------------------------
     humanReviewCompleted: "false"
     ```

   - Embedded `scoring.yaml` containing `labelKeys` with
     `archetype: vdr.fedramp.io/security-requirements`, the complete 27-entry
     catalog from `derive_requirements.py --emit-catalog`, assignment rules
     for every inventoried workload (exact `nameRules` by default; narrow
     patterns, `namespaceRules`, `kindRules` only under the guide's
     uniformity gates; explicit rules for standalone and Helm-hook Jobs; no
     blanket Job fallbacks), `multiAgencyNamespaces` when namespace-scoped,
     and `internetAccessibleIngressClasses`/`internetAccessibleGatewayClasses`
     handled exactly as before: emit high-confidence observed or
     operator-confirmed classes; if unanswered, make a conservative best
     guess from active route objects and annotate confidence and manual
     review; omit the keys when the best-supported conclusion is none.
   - A `# confidence:` comment above every rule or coherent rule group, a
     `# manual-review:` comment for every non-high rule, and a
     `# capped:`/`# breakout:` comment on rules whose vector was capped or
     broke out (e.g. `# capped: CR H->M, AR M->L by envelope`).
   - See `assets/vdr-fedramp.example.yaml` for a complete fictional example of
     this shape.
3. `security-objectives.json` — the full derivation record per the guide
   schema.
4. `assignment-coverage.json` — one assignment per inventoried workload per
   the guide schema, plus `configurationAssumptions` for provisional Class,
   multi-agency, or ingress assumptions, and a `summary` with counts by
   namespace, resolution source, status, confidence, capped, and breakout.

If the operator explicitly requests direct-label overrides, also emit
`label-overrides.sh` beginning with `FOR OPERATOR REVIEW AND EXECUTION`,
pinned to the reviewed `--context`, using the
`vdr.fedramp.io/security-requirements` key; for CronJobs put the label in
CronJob `metadata.labels` or
`spec.jobTemplate.spec.template.metadata.labels`, never
`spec.jobTemplate.metadata.labels`.

Do not put PAIN word thresholds in the ConfigMap. If the user supplies a
proprietary-term deny-list, scan generated files case-insensitively.

### 10. Validate without touching the cluster

- Parse the outer YAML and embedded `scoring.yaml`.
- Verify every label value matches `cr-[lmh]_ir-[lmh]_ar-[lmh]`, is dot-free,
  and has a catalog entry whose cr/ir/ar match its encoding; all 27 entries
  present.
- Verify `humanReviewCompleted` is present, `"false"`, and comment-fenced;
  never print its value anywhere.
- Verify confidence comments on `class`, `multiAgency`, emitted or
  provisionally omitted internet-accessibility keys, and every rule;
  manual-review comments wherever confidence is not high.
- Resolve every inventory entry through actual precedence (workload label ->
  namespace label -> nameRule -> kindRule -> namespaceRule -> fail-safe);
  fail if any workload resolves to `unclassified` or an explicit
  security-requirements label carries a value missing from the catalog.
- Verify the inventory equation and that every emitted rule matches at least
  one inventoried workload unless operator-attested forward-looking.
- Run the mandatory gate; a nonzero exit is a validation failure:

  ```bash
  python3 <skill-dir>/scripts/report_confidence.py \
    ./vdr-configmap-output/assignment-coverage.json \
    ./vdr-configmap-output/security-objectives.json
  ```

  It re-verifies the envelope math, capped flags, breakout legitimacy, and
  confidence contract, and prints the manual-review list, capped components,
  and breakouts (explicit `none` when empty).
- When a sibling `trivy-plugin-vdr` checkout is available, prefer an offline
  parser/smoke test against that implementation; treat invalid-cluster-config
  warnings as failures even on exit zero.
- When `label-overrides.sh` exists, run `bash -n` on it.
- Keep the `skills/` and `.agents/skills/` copies byte-identical.
- Never execute any generated artifact.

### 11. Handoff

Report the inventory total, operator-confirmed and agent-inferred counts,
confidence counts, capped-component count, the breakout list, and any
precedence conflicts. Repeat the non-high-confidence manual-review list in
the terminal. Never state the `humanReviewCompleted` value. Tell the operator
to review all four files, apply the ConfigMap manually or through GitOps, and
flip `humanReviewCompleted` to `"true"` only as a deliberate human action
after review. Re-run the skill after estate, system, agency, Class, scope, or
reviewed-assumption changes.
