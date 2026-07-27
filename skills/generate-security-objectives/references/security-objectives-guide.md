# Security objectives assessment guide

Use this guide to marry a system's designed risk profile with the deploying
agency's actual use. The result is one auditable JSON document, not a workload
classification or deployment artifact.

## Model and math

Each vector has Confidentiality, Integrity, and Availability objectives over
`L < M < H`.

- **System Security Objectives (SSO):** what the product holds and does by
  design, including realistic ingestion and contamination paths.
- **Agency Security Objectives (ASO):** what a definite deploying agency will
  actually place in this system, evaluated per objective. It is not the
  agency's overall FIPS 199 high-water mark.
- **NIST SP 800-60 information types:** provisional impact recommendations
  aligned to FIPS 199. Confirmed matches inform SSO and ASO; they do not decide
  either vector on their own.
- **Security-requirements ceiling:** optional downstream metadata derived per
  objective:

  ```text
  ceiling(o) = min(SSO(o), ASO(o))
  ```

The ceiling never replaces asset archetypes. When supplied to
`trivy-plugin-vdr`, it caps each resolved archetype objective only for PAIN
calculation. A higher ceiling does not raise an archetype objective.

## Calibration rules

- Federal-government-sourced records are a primary High driver for C and I.
- Raw vulnerability and change-management data start at C:M. Raise it only
  with a documented data driver.
- Assess availability against complete logical loss, including durable
  records, not only transient downtime. Reserve A:L for genuinely
  reconstructible or ephemeral systems.
- Uploads, attachments, free text, email ingestion, and agency-system feeds
  can raise SSO because they allow higher-impact content into the boundary.
- Software installed on agency endpoints expands the system consequence and
  should be reflected in system integrity and availability reasoning.
- Replicas, backups, and failover are mitigations. They do not lower the
  inherent objective being measured.
- NIST SP 800-60 base profiles are provisional. The record's special factors,
  actual data, aggregation, use, system context, and governing sources can
  raise or otherwise modify them.

## NIST SP 800-60 information-type evidence

The bundled catalog is a source-traceable conversion of NIST SP 800-60 Volume
II Revision 1. It contains 170 management/support and mission-based records:
168 security-category statements and two delivery mechanisms without a
standalone impact profile. Each categorized record preserves its description,
provisional C/I/A profile, objective rationale, special factors, recommendation,
taxonomy, and PDF/document page references.

Query narrowly rather than reading the whole JSON:

```bash
python3 <skill-dir>/scripts/query_nist_800_60.py --search "health care"
python3 <skill-dir>/scripts/query_nist_800_60.py --id D.14.4 --json
python3 <skill-dir>/scripts/query_nist_800_60.py --impact L,H,- --limit 20
```

Apply a result as follows:

1. Search system functions, records, transactions, and agency use separately.
2. Treat matches as candidates until the operator or direct evidence confirms
   that the information enters the assessed boundary.
3. For a confirmed type, copy the catalog ID, exact name, and provisional
   profile. Read all three objective rationales and special factors.
4. Produce an applied profile from actual use. Record which special factors
   and contextual adjustments were considered and why the applied result
   differs, if it does.
5. Use the per-objective maximum of confirmed applied profiles as one input to
   SSO or the agency profile's ASO. Then account for contamination paths,
   aggregation, trusted actions, durable loss, and governing sources.

Never lower a direct categorization or stronger evidence just because a
catalog base profile is lower. A candidate or excluded match does not
participate in objective math. `C.3.5.9 Information Sharing` has N/A objectives
because the shared information types carry the impact. `D.26.1` and `D.26.2`
are delivery mechanisms and have no standalone profile. Classified information
and national-security systems are outside this publication's scope.

## Starting profiles

These are conversation starters, never conclusions. Confirm or adjust all
three objectives from evidence.

| System type | C | I | A | Typical drivers |
|---|---:|---:|---:|---|
| Project and portfolio management | M | M | M | Aggregated planning and durable records |
| Legal case management | H | H | M | Privileged material and legally operative records |
| Electronic medical records | H | H | H | Health records and care delivery |
| Security operations / SIEM | M | H | H | Telemetry, alert integrity, protection availability |
| Endpoint management | M | H | H | Control and update channel to managed endpoints |
| Identity / SSO | H | H | H | Credentials and durable trust material |
| Vulnerability management | M | M | M | Vulnerability-data C:M baseline |
| Change management / ITSM | M | M | M | Production-driving change records |
| Document / records management | L-H | M | M | Confidentiality tracks the stored corpus |
| Learning management | L-M | M | L-M | Public content; rosters may raise C |

## Question bank

Ask each question with its why. Missing answers do not block the artifact:
make the strongest evidence-backed inference, state it as an assumption, lower
confidence, and add a concrete review action.

### Phase A: system profile to SSO

1. What product and offering is being assessed, and may I research its public
   documentation?
   *Why: designed purpose and data paths establish the SSO starting point.*
2. Here is the description I derived. What is wrong or missing?
   *Why: the operator must confirm or correct researched context.*
3. Which data types can be stored or transited: federal records, PII,
   sensitive PII, CUI, tax, health, criminal-justice, privileged legal,
   financial/confidential business, security telemetry, change/configuration,
   or public content?
   *Why: these are direct confidentiality and integrity drivers.*
4. Can uploads, attachments, free text, email, or integrations introduce
   content beyond the designed model?
   *Why: contamination paths can raise SSO.*
5. Does the system install or control software on agency devices?
   *Why: compromise can extend beyond the system's stored data.*
6. What trusted decisions or actions depend on the system, and what would
   permanent loss or corruption of its durable records cause?
   *Why: integrity and availability require consequence evidence.*

### Phase B: agency use to ASO

7. Which agencies definitely use this deployment? “None yet” is valid.
   *Why: only definite use participates in ASO aggregation.*
8. If none is definite, which agencies are being targeted?
   *Why: targets can guide a low-confidence estimate but do not become
   definite use.*
9. For each agency, what data will it actually place in this product and which
   statutory or contractual overlays apply?
   *Why: real use and binding overlays determine the objective profile.*
10. Is an objective-level categorization available from an authorization
    package, solicitation, privacy assessment, or other governing source?
    *Why: direct categorization is stronger than an estimate.*
11. What authorization does the offering hold: Ready, Low, Moderate, High, or
    unknown?
    *Why: Class is a useful prior and remediation input, but not authority over
    the ASO.*

## Class divergence protocol

Apply independently for C, I, and A:

1. Build ASO from agency use without looking at Class.
2. Map the Class prior: D→H, C→M, B→L, A→L, unknown→none.
3. Compare:
   - agreement: record Class as corroboration;
   - estimate below the prior: surface the divergence and request an operator
     attestation about this deployment. A confirmed lower value wins.
     Without an answer, use the higher prior at low confidence and record
     review;
   - estimate above the prior: retain the estimate. Class never caps actual
     agency-use evidence; record the authorization mismatch for review.
4. Preserve objective, estimate, prior, resolution, rationale, governing
   source when known, and attestation status in `classPrior.divergences`.

For several definite agencies, compute top-level ASO as the per-objective
maximum after each agency's divergence resolution. Target-only profiles do not
participate. If no agency is definite, set ASO equal to SSO at low confidence
and record that fallback in `agencyUseSummary` assumptions and manual review.

## Confidence

Confidence describes evidence quality, never impact severity.

| Confidence | Use when | Record |
|---|---|---|
| high | Direct operator attestation or governing source supports all objectives | Evidence and no unresolved review |
| medium | Purpose is supported but an objective uses a conventional inference | Assumption and verification action |
| low | Evidence is sparse, conflicting, target-only, or unanswered | Strongest credible value and what would change it |

When two adjacent values remain credible, select the higher one and state what
evidence would justify lowering it.

## JSON contract

Write exactly one `security-objectives.json`:

```json
{
  "schemaVersion": 1,
  "systemProfile": {
    "product": "generic product",
    "confirmedDescription": "operator-confirmed purpose and data summary",
    "dataTypes": ["..."],
    "contaminationPaths": ["..."],
    "agencyDeviceFootprint": {"present": false, "details": []},
    "nistInformationTypes": [{
      "id": "C.2.3.4",
      "name": "Strategic Planning",
      "applicability": "confirmed",
      "provisionalImpact": {"c": "L", "i": "L", "a": "L"},
      "appliedImpact": {"c": "M", "i": "M", "a": "M"},
      "specialFactorsConsidered": [
        "The deployment aggregates non-public draft plans and durable records."
      ],
      "rationale": "Deployment context raises the provisional profile."
    }],
    "sso": {
      "c": {"level": "M", "rationale": "..."},
      "i": {"level": "M", "rationale": "..."},
      "a": {"level": "M", "rationale": "..."}
    },
    "status": "operator-confirmed",
    "confidence": "high",
    "assumptions": [],
    "manualReview": []
  },
  "agencyProfiles": [{
    "agency": "deploying agency",
    "relationship": "definite",
    "overlays": [],
    "nistInformationTypes": [{
      "id": "C.2.3.4",
      "name": "Strategic Planning",
      "applicability": "confirmed",
      "provisionalImpact": {"c": "L", "i": "L", "a": "L"},
      "appliedImpact": {"c": "M", "i": "M", "a": "L"},
      "specialFactorsConsidered": [
        "This agency stores non-public planning material."
      ],
      "rationale": "Actual agency use raises C and I; records are reconstructible."
    }],
    "aso": {
      "c": {"level": "M", "rationale": "..."},
      "i": {"level": "M", "rationale": "..."},
      "a": {"level": "L", "rationale": "..."}
    },
    "status": "operator-confirmed",
    "confidence": "high",
    "assumptions": [],
    "manualReview": []
  }],
  "agencyUseSummary": {
    "basis": "definite-agencies",
    "rationale": "ASO is the per-objective maximum for definite deploying agencies.",
    "status": "operator-confirmed",
    "confidence": "high",
    "assumptions": [],
    "manualReview": []
  },
  "classPrior": {
    "class": "C",
    "authorization": "FedRAMP Moderate",
    "divergences": []
  },
  "sso": {"c": "M", "i": "M", "a": "M"},
  "aso": {"c": "M", "i": "M", "a": "L"},
  "securityRequirementsCeiling": {
    "c": "M",
    "i": "M",
    "a": "L",
    "wire": "cr-m_ir-m_ar-l",
    "display": "CR:M/IR:M/AR:L"
  }
}
```

Rules enforced by `validate_security_objectives.py`:

- `systemProfile.sso` levels equal top-level SSO.
- Optional `nistInformationTypes` entries use exact catalog IDs, names, and
  provisional profiles. Confirmed categorized entries require an applied
  C/I/A profile; candidate and excluded entries cannot be applied.
- Definite agency profiles aggregate to top-level ASO using per-objective max.
  With none, `agencyUseSummary.basis` is `sso-fallback`, confidence is low,
  manual review is non-empty, and ASO equals SSO.
- The ceiling equals per-objective `min(SSO, ASO)` and its `wire` and `display`
  encodings match.
- Class is A, B, C, D, or `unknown`.
- Every profile carries status, confidence, assumptions, and manual-review
  fields.
- Component, assignment, ConfigMap, envelope, and multi-agency fields are
  rejected; they belong to other workflows.

## Optional downstream handoff

The assessment is complete even if the ceiling is never used. If selected,
copy only the `wire` value into either:

- `vdr-fedramp` ConfigMap data key `securityRequirementsCeiling`; or
- trivy-plugin-vdr flag `--security-requirements-ceiling`.

The runtime flag has precedence over the ConfigMap value. Reports normalize
the value as `CR:H/IR:M/AR:L` and mark PAIN as recalculated only when the
ceiling actually lowers an archetype objective.
