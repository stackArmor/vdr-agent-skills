---
name: generate-security-objectives
description: Evaluate a system's security objectives together with the deploying agency's expected use, use NIST SP 800-60/FIPS 199 information types as provisional evidence, apply a transparent FedRAMP Class divergence protocol, and write one validated security-objectives.json artifact containing SSO, ASO, and the optional downstream security-requirements ceiling. Use when an operator needs a risk-profile assessment, federal information-type classification, or ceiling for trivy-plugin-vdr, without generating a ConfigMap, inventorying workloads, or assigning component archetypes.
---

# Generate Security Objectives

Interview the operator and write one evidence-backed assessment:
`./vdr-security-objectives-output/security-objectives.json`.

Read `references/security-objectives-guide.md` completely before starting. It
defines the model, calibration, question bank, divergence protocol, confidence
rules, and exact JSON contract. Resolve `<skill-dir>` to this file's directory.

Use the bundled machine-readable NIST SP 800-60 Volume II Revision 1 catalog
through the query script; do not load its 170 full narrative records into
context:

```bash
python3 <skill-dir>/scripts/query_nist_800_60.py --search "<data or function>"
python3 <skill-dir>/scripts/query_nist_800_60.py --id D.14.4 --json
```

## Boundaries

- Produce only `security-objectives.json`. Do not generate or edit a
  ConfigMap, workload label, archetype, component assignment, coverage ledger,
  or infrastructure file.
- Do not access Kubernetes or any cloud account. This assessment does not need
  a runtime inventory.
- Ask before public web research. Present researched descriptions and
  objective estimates for operator confirmation. If consent is declined, use
  operator-provided information and lower confidence where appropriate.
- Preserve operator attestations separately from agent inferences. Record
  evidence, assumptions, confidence, and concrete manual-review items.
- Confidence measures evidence quality and never lowers an objective.
- NIST SP 800-60 recommendations are informative starting points. Confirm
  applicability, consider the record's special factors, and adjust from actual
  system and agency use. They never override a governing categorization or
  operator evidence.
- Do not use the catalog for classified information or national-security
  systems; those are outside the publication's scope.
- The derived ceiling is optional downstream metadata. Do not warn if the
  operator elects not to use it.
- No real product, vendor, or agency names belong in reusable skill content.
  Runtime output naturally contains the operator's actual names.

## Workflow

### 1. Establish the system profile

Run guide Phase A:

1. Identify the product and request research consent.
2. Confirm the product purpose and designed data profile.
3. Assess data types, contamination paths, agency-device footprint, trusted
   decisions, and consequences of complete logical loss.
4. Query the NIST catalog using the system's designed functions and data.
   Confirm candidate information types with the operator, inspect their
   special factors, and record confirmed, candidate, or excluded matches under
   `systemProfile.nistInformationTypes`.
5. Use confirmed NIST profiles and the system-type profile only as starting
   evidence, then adjust each objective from actual system context.

Record the detailed rationale under `systemProfile.sso` and the normalized
letters under top-level `sso`.

### 2. Establish agency use

Run guide Phase B for every definite deploying agency. Target agencies may
inform a profile but are not treated as definite use.

Estimate each objective from what that agency will actually put into this
system, including governing overlays and known objective-level
categorization. Never substitute the agency-wide FIPS 199 high-water mark.
Query and confirm NIST information types for that agency's actual use, and
record the provisional and applied profiles under the agency's
`nistInformationTypes`. Apply each record's special factors before taking the
per-objective maximum of confirmed applicable types as an ASO input.
For multiple definite agencies, top-level ASO is the per-objective maximum.
With no definite agency, set ASO equal to SSO at low confidence and record the
assumption for review. Record the aggregation or fallback basis under
`agencyUseSummary`.

### 3. Reconcile the Class prior

Ask for the authorization Class (Ready A, Low B, Moderate C, High D), or record
`unknown`. Apply the guide's divergence protocol independently to C, I, and A.
Class is a prior and deadline input, not authority over the data profile.
Preserve every divergence and its resolution under `classPrior.divergences`.

### 4. Derive the optional ceiling

Create a draft JSON following the guide schema, then compute rather than guess:

```bash
python3 <skill-dir>/scripts/derive_ceiling.py \
  ./vdr-security-objectives-output/security-objectives.json
```

Per objective:

```text
securityRequirementsCeiling(o) = min(SSO(o), ASO(o))
```

Insert the script's result as `securityRequirementsCeiling`. It includes the
letter objectives, transport-safe `wire`, and normalized `display` form.

### 5. Validate

Run:

```bash
python3 <skill-dir>/scripts/validate_security_objectives.py \
  ./vdr-security-objectives-output/security-objectives.json
```

Fix every validation error. The validator rejects component or ConfigMap-era
fields so this artifact cannot silently expand beyond its intended scope.

### 6. Hand off

Summarize SSO, ASO, the ceiling, confidence, assumptions, and unresolved review
items. State that ceiling use is optional. If the operator wants to use it,
show—but do not write—either handoff:

```yaml
data:
  securityRequirementsCeiling: cr-m_ir-m_ar-l
```

```bash
trivy vdr <mode> --security-requirements-ceiling cr-m_ir-m_ar-l ...
```

Use the actual derived wire value. Explain that trivy-plugin-vdr retains the
asset archetype and only recalculates reported PAIN scores where an archetype
objective exceeds the declared ceiling. The report displays the normalized
ceiling and whether recalculation occurred.
