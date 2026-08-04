# generate-cloud-vdr-config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `generate-cloud-vdr-config` skill that discovers CIS-addressed GCP/AWS resources read-only, and emits the central `vdr-cloud.yaml` (`CloudResourceScoringConfig`) assignment surface plus inventory and coverage ledgers, per the approved spec `docs/superpowers/specs/2026-08-04-cloud-resource-scoring-config-design.md`.

**Architecture:** Three stdlib-only Python scripts do the mechanical work: `inventory_cloud_resources.py` (per-scope CLI discovery + built-in pattern annotation + tag mining + merge), `render_cloud_config.py` (deterministic JSON-plan → commented YAML rendering, so no YAML parser is ever needed), and `validate_cloud_config.py` (SIP validation via the sibling skill's governed `reason_codes.py`, full resolution replay, inventory-equation accounting, confidence report). The agent authors the assignment plan JSON (judgment); scripts render and validate (mechanics).

**Tech Stack:** Python 3.8+ standard library only; `gcloud` and `aws` CLIs invoked read-only via subprocess; `unittest` tests in `tests/`.

## Global Constraints

- Python >= 3.8, **standard library only** — no pip installs, no PyYAML. YAML is only ever *written* (rendered), never parsed.
- Cloud access is **read-only**: only `list`, `describe`, `get`, `sts get-caller-identity`, `gcloud config get-value`, `gcloud auth list`, `gcloud projects list`, `gcloud asset list`. Never any mutating verb.
- Never write secret material into artifacts (no instance user-data, no env values, no credentials).
- SIP values use canonical dotted form inside all JSON/YAML artifacts. Provider encodings (GCP `vdr_fedramp_io_*` keys, `__` trace separators) are decoded during discovery per `skills/tag-terraform-vdr-assets/references/cis-asset-map.md`.
- Fail-closed provisional defaults when unattested: `class: "D"`, `multiAgency: "true"`.
- `class` and `multiAgency` are quoted strings everywhere ("A"–"D", "true"/"false").
- Confidence levels are exactly `high|medium|low`; every non-high item needs at least one manual-review string.
- Built-in pattern rules are capped at `medium` confidence; default trace is `service-content.disposable-state.deferrable-work` (M/L/L).
- `skills/generate-cloud-vdr-config/` and `.agents/skills/generate-cloud-vdr-config/` must end byte-identical.
- Commit messages never reference Claude, AI, or agents; write them as the repository owner.
- Run the full suite with: `python3 -m unittest discover -s tests -v` (from repo root).

## File Structure

```
skills/generate-cloud-vdr-config/
  SKILL.md                                   # operator workflow (Task 6)
  references/
    cloud-config-schema.md                   # schema, precedence, identifier table (Task 6)
    managed-resource-patterns.json           # governed pattern catalog (Task 1)
    managed-resource-patterns.md             # prose guide to the catalog (Task 6)
  scripts/
    inventory_cloud_resources.py             # discovery + patterns + merge (Tasks 2-3)
    render_cloud_config.py                   # plan JSON -> vdr-cloud.yaml (Task 4)
    validate_cloud_config.py                 # replay + accounting + report (Task 5)
  assets/
    vdr-cloud.example.yaml                   # rendered fictional example (Task 6)
tests/
  test_managed_resource_patterns.py          # Task 1
  test_inventory_cloud_resources.py          # Tasks 2-3
  test_render_cloud_config.py                # Task 4
  test_validate_cloud_config.py              # Task 5
.agents/skills/generate-cloud-vdr-config/    # byte-identical copy (Task 7)
```

## Shared data shapes (used by every task)

**Inventory document** (`resource-inventory.json`), produced by Task 2/3:

```json
{
  "scopes": [
    {
      "provider": "gcp",
      "project": "acme-prod",
      "provenance": {"callerIdentity": "ops@acme.example", "profile": null,
                     "resolvedScope": "acme-prod", "inventorySource": "asset-api"},
      "resources": [
        {"type": "storage.googleapis.com/Bucket",
         "identifier": "gcf-sources-123-us-central1",
         "region": "us-central1", "network": null, "subnet": null,
         "tags": {"goog-managed-by": "cloudfunctions"},
         "vdrTags": {},
         "builtinPatterns": ["gcp-cloudfunctions-staging"]}
      ],
      "tagSummary": {"goog-managed-by": {"count": 1, "values": {"cloudfunctions": 1}}},
      "warnings": []
    }
  ],
  "summary": {"scopeCount": 1, "resourceCount": 1, "byType": {"storage.googleapis.com/Bucket": 1}}
}
```

AWS scopes use `"account": "123456789012"` instead of `project`, and `provenance.profile` holds the CLI profile name. `vdrTags` always holds **canonical** keys after decoding.

**Assignment plan** (`assignment-plan.json`), authored by the agent, consumed by render + validate:

```json
{
  "defaults": {
    "class": {"value": "C", "confidence": "high", "evidence": "operator-confirmed FedRAMP Moderate", "manualReview": []},
    "multiAgency": {"value": "false", "confidence": "high", "evidence": "operator-confirmed single agency", "manualReview": []},
    "securityImpactProfile": null
  },
  "archetypes": {},
  "scopes": [
    {
      "provider": "gcp",
      "project": "acme-prod",
      "class": {"value": "C", "confidence": "high", "evidence": "operator-confirmed", "manualReview": []},
      "multiAgency": {"value": "false", "confidence": "high", "evidence": "operator-confirmed", "manualReview": []},
      "securityImpactProfile": null,
      "nameRules": [
        {"type": "storage.googleapis.com/Bucket", "match": "gcf-sources-*",
         "securityImpactProfile": "service-content.disposable-state.deferrable-work",
         "multiAgency": null, "region": null, "matchTags": null,
         "confidence": "medium", "builtinPattern": "gcp-cloudfunctions-staging",
         "evidence": "provider-created transient artifact store",
         "manualReview": ["attest CR down with a direct vector only after verifying staged contents are non-sensitive",
                           "confirm nothing re-consumes artifacts post-deploy (would raise IR)"]}
      ],
      "tagRules": [],
      "networkRules": [],
      "typeRules": []
    }
  ]
}
```

Rule-family field sets: `nameRules` = `type` (recommended), `match` (required), optional `matchTags`, `region`; `tagRules` = `matchTags` (required), optional `type`, `region`; `networkRules` = `network` (required), optional `subnet`, `type`; `typeRules` = `type` (required), optional `region`. Every rule may set `securityImpactProfile`, `multiAgency`, or both (at least one required). `type` compares **exactly**; `match`, `matchTags` values, `network`, `subnet`, `region` use `fnmatch.fnmatchcase` globs.

**Coverage ledger** (`assignment-coverage.json`), authored by the agent, checked by Task 5:

```json
{
  "scopes": ["gcp/acme-prod"],
  "inventoryTotal": 1,
  "assignments": [
    {"scope": "gcp/acme-prod", "type": "storage.googleapis.com/Bucket",
     "identifier": "gcf-sources-123-us-central1",
     "securityImpactProfile": "service-content.disposable-state.deferrable-work",
     "derivationMethod": "decision-trace", "vector": "M/L/L",
     "resolutionSource": "nameRules[0]", "multiAgency": "false",
     "multiAgencySource": "scope-default",
     "status": "builtin-pattern", "confidence": "medium",
     "evidence": "provider-created transient artifact store",
     "assumptions": ["bucket contents are deploy-time only"],
     "manualReview": ["attest CR down with a direct vector only after verifying staged contents are non-sensitive"]}
  ],
  "configurationAssumptions": [],
  "summary": {"byScope": {"gcp/acme-prod": 1}, "byFamily": {"nameRules": 1},
              "byStatus": {"builtin-pattern": 1}, "byConfidence": {"medium": 1}}
}
```

Scope key format everywhere: `"<provider>/<project-or-account>"`.

---

### Task 1: Managed-resource pattern catalog

**Files:**
- Create: `skills/generate-cloud-vdr-config/references/managed-resource-patterns.json`
- Test: `tests/test_managed_resource_patterns.py`

**Interfaces:**
- Produces: the catalog JSON — a list of objects with keys `id`, `provider` (`gcp|aws`), `type`, `nameGlobs` (list), `markerTags` (object), `managedBy`, `rationale`, `defaultSecurityImpactProfile`, `maxConfidence` (always `"medium"`), `manualReview` (non-empty list). Tasks 2-3 load it to annotate resources; Task 6 documents it.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_managed_resource_patterns.py
import json
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG = (REPO_ROOT / "skills" / "generate-cloud-vdr-config"
           / "references" / "managed-resource-patterns.json")
REASON_CODES = (REPO_ROOT / "skills" / "generate-vdr-configmap"
                / "scripts" / "reason_codes.py")


def load_reason_codes():
    spec = importlib.util.spec_from_file_location("vdr_reason_codes", REASON_CODES)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManagedResourcePatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = json.loads(CATALOG.read_text(encoding="utf-8"))
        cls.reason_codes = load_reason_codes()

    def test_catalog_shape(self):
        required = {"id", "provider", "type", "nameGlobs", "markerTags",
                    "managedBy", "rationale", "defaultSecurityImpactProfile",
                    "maxConfidence", "manualReview"}
        ids = set()
        for entry in self.patterns:
            self.assertEqual(required, set(entry), entry.get("id"))
            self.assertIn(entry["provider"], ("gcp", "aws"))
            self.assertEqual(entry["maxConfidence"], "medium", entry["id"])
            self.assertTrue(entry["nameGlobs"] or entry["markerTags"], entry["id"])
            self.assertTrue(entry["manualReview"], entry["id"])
            self.assertNotIn(entry["id"], ids)
            ids.add(entry["id"])

    def test_default_traces_validate_against_governed_registry(self):
        for entry in self.patterns:
            vector = self.reason_codes.classify(entry["defaultSecurityImpactProfile"])
            self.assertEqual(("M", "L", "L"), vector, entry["id"])

    def test_expected_patterns_present(self):
        ids = {entry["id"] for entry in self.patterns}
        for expected in ("gcp-cloudfunctions-staging", "gcp-cloudbuild-artifacts",
                         "gcp-cloudrun-sources", "gcp-dataproc-staging",
                         "gcp-container-registry-artifacts", "gcp-appengine-staging",
                         "aws-cloudformation-templates", "aws-cdk-assets",
                         "aws-elasticbeanstalk-artifacts", "aws-athena-query-results",
                         "aws-cloudformation-managed"):
            self.assertIn(expected, ids)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_managed_resource_patterns -v`
Expected: FAIL (`FileNotFoundError` reading the catalog).

- [ ] **Step 3: Write the catalog**

Create `managed-resource-patterns.json` with exactly these eleven entries (all share `"defaultSecurityImpactProfile": "service-content.disposable-state.deferrable-work"`, `"maxConfidence": "medium"`, and this shared manual-review pair unless noted):

Shared `manualReview`:
```json
["attest CR down with a direct vector only after verifying staged contents embed no credentials or sensitive material",
 "confirm nothing re-consumes these artifacts after deployment (re-consumption raises IR)"]
```

| id | provider | type | nameGlobs | markerTags | managedBy |
|---|---|---|---|---|---|
| gcp-cloudfunctions-staging | gcp | storage.googleapis.com/Bucket | `["gcf-sources-*", "gcf-v2-sources-*"]` | `{}` | Cloud Functions |
| gcp-cloudbuild-artifacts | gcp | storage.googleapis.com/Bucket | `["*_cloudbuild"]` | `{}` | Cloud Build |
| gcp-cloudrun-sources | gcp | storage.googleapis.com/Bucket | `["run-sources-*"]` | `{}` | Cloud Run |
| gcp-dataproc-staging | gcp | storage.googleapis.com/Bucket | `["dataproc-staging-*", "dataproc-temp-*"]` | `{}` | Dataproc |
| gcp-container-registry-artifacts | gcp | storage.googleapis.com/Bucket | `["artifacts.*.appspot.com"]` | `{}` | Container Registry |
| gcp-appengine-staging | gcp | storage.googleapis.com/Bucket | `["staging.*.appspot.com"]` | `{}` | App Engine |
| gcp-managed-by-label | gcp | storage.googleapis.com/Bucket | `[]` | `{"goog-managed-by": "*"}` | GCP service (per label value) |
| aws-cloudformation-templates | aws | AWS::S3::Bucket | `["cf-templates-*"]` | `{}` | CloudFormation |
| aws-cdk-assets | aws | AWS::S3::Bucket | `["cdk-*-assets-*"]` | `{}` | AWS CDK bootstrap |
| aws-elasticbeanstalk-artifacts | aws | AWS::S3::Bucket | `["elasticbeanstalk-*"]` | `{}` | Elastic Beanstalk |
| aws-athena-query-results | aws | AWS::S3::Bucket | `["aws-athena-query-results-*"]` | `{}` | Athena |

Plus one marker-tag pattern spanning types: `aws-cloudformation-managed`, provider `aws`, type `*` (matches any type), `nameGlobs: []`, `markerTags: {"aws:cloudformation:stack-name": "*"}`, managedBy `CloudFormation`, with an extra first manual-review line: `"the owning stack defines this resource's real role; classify by the stack's purpose, not this default"`. Note: the test above expects 11 ids listed plus `gcp-managed-by-label` = 12 entries total; `test_expected_patterns_present` names 11 and `gcp-managed-by-label` is covered by `test_catalog_shape`. Each entry's `rationale` is one sentence stating which service auto-creates the resource and why tagging control is limited.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_managed_resource_patterns -v` — Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add skills/generate-cloud-vdr-config/references/managed-resource-patterns.json tests/test_managed_resource_patterns.py
git commit -m "Add managed-resource pattern catalog for cloud VDR config"
```

---

### Task 2: Inventory script — core + GCP discovery

**Files:**
- Create: `skills/generate-cloud-vdr-config/scripts/inventory_cloud_resources.py`
- Test: `tests/test_inventory_cloud_resources.py`

**Interfaces:**
- Consumes: `managed-resource-patterns.json` (Task 1 shape).
- Produces (module functions Task 3 extends and tests import via `importlib`):
  - `run_command(args: list) -> str` — subprocess wrapper returning stdout, raises `RuntimeError` on nonzero exit. Tests monkeypatch this.
  - `load_patterns(path: Path) -> list`
  - `match_patterns(resource: dict, patterns: list) -> list[str]` — sorted pattern ids whose provider+type match and (any nameGlob matches identifier OR all markerTags match tags).
  - `decode_vdr_tags(provider: str, tags: dict) -> dict` — canonical `vdr.fedramp.io/*` keys found in raw tags; GCP: decode `vdr_fedramp_io_security_impact_profile` etc. and `__`→`.` in trace values; AWS: canonical keys pass through.
  - `summarize_tags(resources: list) -> dict` — `{key: {"count": n, "values": {value: n}}}`.
  - `inventory_gcp(project: str, patterns: list, runner=run_command, use_asset_api=True) -> dict` — one scope document.
  - `merge_scopes(scope_docs: list) -> dict` — full inventory document with `summary`.
  - CLI: `--provider gcp --project P [--no-asset-api] [--output FILE]`, or `--merge scope1.json scope2.json --output FILE`. `--patterns` defaults to the sibling references path.
- GCP asset types constant `GCP_ASSET_TYPES`: `storage.googleapis.com/Bucket`, `compute.googleapis.com/Instance`, `sqladmin.googleapis.com/Instance`, `bigquery.googleapis.com/Dataset`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_inventory_cloud_resources.py
import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL = REPO_ROOT / "skills" / "generate-cloud-vdr-config"


def load_script(stem):
    path = SKILL / "scripts" / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fake_runner(responses):
    """responses: list of (subcommand-match, payload). Raises on no match."""
    calls = []

    def run(args):
        calls.append(args)
        joined = " ".join(args)
        for needle, payload in responses:
            if needle in joined:
                return payload if isinstance(payload, str) else json.dumps(payload)
        raise RuntimeError("unexpected command: " + joined)

    run.calls = calls
    return run


class PatternMatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("inventory_cloud_resources")
        cls.patterns = cls.mod.load_patterns(
            SKILL / "references" / "managed-resource-patterns.json")

    def test_name_glob_match(self):
        resource = {"type": "storage.googleapis.com/Bucket",
                    "identifier": "gcf-sources-42-us-central1", "tags": {}}
        self.assertIn("gcp-cloudfunctions-staging",
                      self.mod.match_patterns(resource, [p for p in self.patterns
                                                          if p["provider"] == "gcp"]))

    def test_marker_tag_match_any_type(self):
        resource = {"type": "AWS::EC2::Instance", "identifier": "i-0abc",
                    "tags": {"aws:cloudformation:stack-name": "web"}}
        aws = [p for p in self.patterns if p["provider"] == "aws"]
        self.assertEqual(["aws-cloudformation-managed"],
                         self.mod.match_patterns(resource, aws))

    def test_no_match(self):
        resource = {"type": "storage.googleapis.com/Bucket",
                    "identifier": "acme-prod-customer-data", "tags": {}}
        gcp = [p for p in self.patterns if p["provider"] == "gcp"]
        self.assertEqual([], self.mod.match_patterns(resource, gcp))


class DecodeVdrTagTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("inventory_cloud_resources")

    def test_gcp_encoded_trace_decodes(self):
        tags = {"vdr_fedramp_io_security_impact_profile":
                "service-content__disposable-state__deferrable-work",
                "env": "prod"}
        self.assertEqual(
            {"vdr.fedramp.io/security-impact-profile":
             "service-content.disposable-state.deferrable-work"},
            self.mod.decode_vdr_tags("gcp", tags))

    def test_gcp_direct_vector_and_class_decode(self):
        tags = {"vdr_fedramp_io_security_impact_profile": "cr-l_ir-l_ar-l",
                "vdr_fedramp_io_class": "c",
                "vdr_fedramp_io_multi_agency": "false"}
        decoded = self.mod.decode_vdr_tags("gcp", tags)
        self.assertEqual("cr-l_ir-l_ar-l",
                         decoded["vdr.fedramp.io/security-impact-profile"])
        self.assertEqual("C", decoded["vdr.fedramp.io/class"])
        self.assertEqual("false", decoded["vdr.fedramp.io/multi-agency"])

    def test_aws_canonical_passthrough(self):
        tags = {"vdr.fedramp.io/multi-agency": "true", "Name": "web-1"}
        self.assertEqual({"vdr.fedramp.io/multi-agency": "true"},
                         self.mod.decode_vdr_tags("aws", tags))


class GcpInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("inventory_cloud_resources")
        cls.patterns = cls.mod.load_patterns(
            SKILL / "references" / "managed-resource-patterns.json")

    def asset(self, asset_type, name, location="us-central1", labels=None,
              network=None):
        resource = {"data": {"labels": labels or {}}, "location": location}
        if network:
            resource["data"]["networkInterfaces"] = [
                {"network": network, "subnetwork": network + "/sub"}]
        return {"assetType": asset_type,
                "name": "//x/" + name,
                "resource": resource}

    def test_asset_api_inventory(self):
        runner = fake_runner([
            ("auth list", [{"account": "ops@acme.example", "status": "ACTIVE"}]),
            ("asset list", [
                self.asset("storage.googleapis.com/Bucket",
                           "projects/_/buckets/gcf-sources-42-uc1"),
                self.asset("compute.googleapis.com/Instance",
                           "projects/acme/zones/us-central1-a/instances/web-1",
                           labels={"env": "prod"},
                           network=".../networks/prod-vpc"),
            ]),
        ])
        scope = self.mod.inventory_gcp("acme-prod", self.patterns, runner=runner)
        self.assertEqual("gcp", scope["provider"])
        self.assertEqual("acme-prod", scope["project"])
        self.assertEqual("asset-api", scope["provenance"]["inventorySource"])
        self.assertEqual(2, len(scope["resources"]))
        bucket = scope["resources"][0]
        self.assertEqual("gcf-sources-42-uc1", bucket["identifier"])
        self.assertEqual(["gcp-cloudfunctions-staging"], bucket["builtinPatterns"])
        vm = scope["resources"][1]
        self.assertEqual("web-1", vm["identifier"])
        self.assertEqual("prod-vpc", vm["network"])
        # every gcloud call pins the reviewed project
        for call in runner.calls:
            if "asset list" in " ".join(call):
                self.assertIn("--project", call)
                self.assertIn("acme-prod", call)

    def test_fallback_records_degraded_warning(self):
        runner = fake_runner([
            ("auth list", [{"account": "ops@acme.example", "status": "ACTIVE"}]),
            ("storage buckets list", [{"name": "acme-data", "location": "US",
                                        "labels": {}}]),
            ("sql instances list", []),
            ("compute instances list", []),
            ("bq ", []),
        ])
        scope = self.mod.inventory_gcp("acme-prod", self.patterns,
                                       runner=runner, use_asset_api=False)
        self.assertEqual("per-service-fallback",
                         scope["provenance"]["inventorySource"])
        self.assertTrue(any("Asset" in w or "asset" in w
                            for w in scope["warnings"]))
        self.assertEqual(1, len(scope["resources"]))

    def test_merge_scopes_summary(self):
        scope = {"provider": "gcp", "project": "p", "provenance": {},
                 "resources": [{"type": "t", "identifier": "a", "tags": {},
                                "vdrTags": {}, "builtinPatterns": [],
                                "region": None, "network": None, "subnet": None}],
                 "tagSummary": {}, "warnings": []}
        doc = self.mod.merge_scopes([scope])
        self.assertEqual(1, doc["summary"]["scopeCount"])
        self.assertEqual(1, doc["summary"]["resourceCount"])
        self.assertEqual({"t": 1}, doc["summary"]["byType"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_inventory_cloud_resources -v`
Expected: FAIL (`FileNotFoundError` loading the script).

- [ ] **Step 3: Implement the script**

Key implementation points (full file, stdlib only — `argparse`, `fnmatch`, `json`, `subprocess`, `sys`, `pathlib`, `collections`):

```python
GCP_ASSET_TYPES = [
    "storage.googleapis.com/Bucket",
    "compute.googleapis.com/Instance",
    "sqladmin.googleapis.com/Instance",
    "bigquery.googleapis.com/Dataset",
]

GCP_KEY_ALIASES = {
    "vdr_fedramp_io_security_impact_profile": "vdr.fedramp.io/security-impact-profile",
    "vdr_fedramp_io_class": "vdr.fedramp.io/class",
    "vdr_fedramp_io_multi_agency": "vdr.fedramp.io/multi-agency",
}


def run_command(args):
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError("command failed: %s\n%s" % (" ".join(args), proc.stderr))
    return proc.stdout


def match_patterns(resource, patterns):
    matched = []
    for entry in patterns:
        if entry["type"] not in ("*", resource["type"]):
            continue
        name_hit = any(fnmatch.fnmatchcase(resource["identifier"], glob)
                       for glob in entry["nameGlobs"])
        marker = entry["markerTags"]
        tag_hit = bool(marker) and all(
            key in resource.get("tags", {}) and
            fnmatch.fnmatchcase(str(resource["tags"][key]), str(value))
            for key, value in marker.items())
        if name_hit or tag_hit:
            matched.append(entry["id"])
    return sorted(matched)


def decode_vdr_tags(provider, tags):
    decoded = {}
    if provider == "gcp":
        for raw_key, canonical in GCP_KEY_ALIASES.items():
            if raw_key not in tags:
                continue
            value = tags[raw_key]
            if canonical.endswith("security-impact-profile") and "__" in value:
                value = value.replace("__", ".")
            if canonical.endswith("/class"):
                value = value.upper()
            decoded[canonical] = value
    else:
        for key, value in tags.items():
            if key.startswith("vdr.fedramp.io/"):
                decoded[key] = value
    return decoded
```

`inventory_gcp(project, patterns, runner=run_command, use_asset_api=True)`:
- provenance: `gcloud auth list --filter=status:ACTIVE --format json` → first `account` as `callerIdentity`; `profile: None`; `resolvedScope: project`.
- asset-api path: `gcloud asset list --project <project> --asset-types <comma-joined GCP_ASSET_TYPES> --content-type resource --format json`. Map each asset: `type` = `assetType`; `identifier` = last `/`-segment of `name`; `region` = `resource.location` (or None); `tags` = `resource.data.labels` (or `resource.data.settings.userLabels` for `sqladmin.googleapis.com/Instance`, or `{}`); `network`/`subnet` = last segment of the first `resource.data.networkInterfaces[0]["network"]`/`["subnetwork"]` when present (Cloud SQL: last segment of `resource.data.settings.ipConfiguration.privateNetwork` when present). If the asset call raises, fall through to the per-service path. Whenever the per-service path is used (failure **or** `use_asset_api=False`), append a warning containing the words `"Cloud Asset API"` naming the project and stating the fallback covers buckets, SQL, compute, and BigQuery only (include the error's first line when there was one).
- per-service fallback (`use_asset_api=False` or asset failure): `gcloud storage buckets list --project P --format json` (type Bucket, identifier `name`, region `location`, tags `labels`), `gcloud sql instances list --project P --format json` (identifier `name`, region `region`, tags `settings.userLabels`, network from `settings.ipConfiguration.privateNetwork`), `gcloud compute instances list --project P --format json` (identifier `name`, region from `zone` last segment minus trailing `-x`, tags `labels`, network from `networkInterfaces[0].network` last segment), `bq ls --project_id P --format json` optional — if `bq` fails, append warning naming BigQuery as not enumerated. `inventorySource: "per-service-fallback"`.
- each resource gets `vdrTags = decode_vdr_tags(provider, tags)` and `builtinPatterns = match_patterns(resource, provider_patterns)`; scope gets `tagSummary = summarize_tags(resources)`.
- Never capture user-data/metadata blobs: for compute instances copy only name/zone/labels/networkInterfaces fields.

`merge_scopes(docs)` builds `{"scopes": docs, "summary": {...}}` counting `scopeCount`, `resourceCount`, `byType`.

CLI `main()`: `--provider {gcp,aws}`, `--project`, `--profile`, `--region` (repeatable), `--no-asset-api`, `--patterns PATH` (default `Path(__file__).parent.parent / "references" / "managed-resource-patterns.json"`), `--merge FILES...`, `--output FILE` (default stdout). `--provider aws` exits with an error message until Task 3. On any required-query failure, exit nonzero — never emit a partial scope.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_inventory_cloud_resources -v` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skills/generate-cloud-vdr-config/scripts/inventory_cloud_resources.py tests/test_inventory_cloud_resources.py
git commit -m "Add GCP cloud-resource inventory script with pattern annotation"
```

---

### Task 3: Inventory script — AWS discovery

**Files:**
- Modify: `skills/generate-cloud-vdr-config/scripts/inventory_cloud_resources.py`
- Test: `tests/test_inventory_cloud_resources.py` (append class)

**Interfaces:**
- Produces: `inventory_aws(profile: str, regions: list, patterns: list, runner=run_command) -> dict` — scope doc with `"account"` key; CLI accepts `--provider aws --profile P --region R [--region R2]`.

- [ ] **Step 1: Write the failing tests (append to the test file)**

```python
class AwsInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_script("inventory_cloud_resources")
        cls.patterns = cls.mod.load_patterns(
            SKILL / "references" / "managed-resource-patterns.json")

    def make_runner(self):
        return fake_runner([
            ("sts get-caller-identity",
             {"Account": "123456789012",
              "Arn": "arn:aws:iam::123456789012:user/ops"}),
            ("s3api list-buckets",
             {"Buckets": [{"Name": "cf-templates-9x-us-east-1"},
                           {"Name": "acme-prod-data"}]}),
            ("s3api get-bucket-tagging",
             {"TagSet": [{"Key": "vdr.fedramp.io/multi-agency",
                           "Value": "true"}]}),
            ("s3api get-bucket-location", {"LocationConstraint": None}),
            ("ec2 describe-instances",
             {"Reservations": [{"Instances": [
                 {"InstanceId": "i-0abc", "VpcId": "vpc-11",
                  "SubnetId": "subnet-22",
                  "Placement": {"AvailabilityZone": "us-east-1a"},
                  "Tags": [{"Key": "Name", "Value": "web-1"},
                            {"Key": "aws:cloudformation:stack-name",
                             "Value": "web"}]}]}]}),
            ("rds describe-db-instances",
             {"DBInstances": [{"DBInstanceIdentifier": "prod-db",
                                "DBSubnetGroup": {"VpcId": "vpc-11"},
                                "AvailabilityZone": "us-east-1a",
                                "TagList": [{"Key": "env", "Value": "prod"}]}]}),
        ])

    def test_aws_inventory(self):
        runner = self.make_runner()
        scope = self.mod.inventory_aws("prod", ["us-east-1"],
                                       self.patterns, runner=runner)
        self.assertEqual("aws", scope["provider"])
        self.assertEqual("123456789012", scope["account"])
        self.assertEqual("prod", scope["provenance"]["profile"])
        by_id = {r["identifier"]: r for r in scope["resources"]}
        self.assertEqual(["aws-cloudformation-templates"],
                         by_id["cf-templates-9x-us-east-1"]["builtinPatterns"])
        self.assertEqual({"vdr.fedramp.io/multi-agency": "true"},
                         by_id["acme-prod-data"]["vdrTags"])
        ec2 = by_id["i-0abc"]
        self.assertEqual("vpc-11", ec2["network"])
        self.assertEqual("subnet-22", ec2["subnet"])
        self.assertIn("aws-cloudformation-managed", ec2["builtinPatterns"])
        self.assertEqual("AWS::RDS::DBInstance", by_id["prod-db"]["type"])
        # every aws call pins the confirmed profile
        for call in runner.calls:
            if call and call[0] == "aws":
                self.assertIn("--profile", call)
                self.assertIn("prod", call)
```

- [ ] **Step 2: Run to verify the new class fails**

Run: `python3 -m unittest tests.test_inventory_cloud_resources.AwsInventoryTests -v`
Expected: FAIL (`AttributeError: ... no attribute 'inventory_aws'`).

- [ ] **Step 3: Implement `inventory_aws`**

- Provenance: `aws sts get-caller-identity --profile P --output json` → `account` = `Account`, `callerIdentity` = `Arn`, `profile` = P, `inventorySource: "per-service"`.
- S3 (global, once): `aws s3api list-buckets --profile P --output json`; per bucket, `get-bucket-tagging` (treat a failing call — no TagSet — as `{}` tags, not an error) and `get-bucket-location` for region (`None` → `us-east-1`). Type `AWS::S3::Bucket`, identifier = bucket name.
- Per region in `regions`: `aws ec2 describe-instances --profile P --region R --output json` → type `AWS::EC2::Instance`, identifier = `InstanceId`, tags from `Tags` list-of-KV → dict, `network` = `VpcId`, `subnet` = `SubnetId`, region = R; `aws rds describe-db-instances --profile P --region R --output json` → type `AWS::RDS::DBInstance`, identifier = `DBInstanceIdentifier`, tags from `TagList`, network = `DBSubnetGroup.VpcId`.
- A failed `sts`, `list-buckets`, `describe-instances`, or `describe-db-instances` call raises (scope fails loud); only per-bucket tagging/location calls degrade to warnings.
- Wire `--provider aws` in `main()`: require `--profile` and at least one `--region`.

- [ ] **Step 4: Run the full test file**

Run: `python3 -m unittest tests.test_inventory_cloud_resources -v` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skills/generate-cloud-vdr-config/scripts/inventory_cloud_resources.py tests/test_inventory_cloud_resources.py
git commit -m "Add AWS profile-pinned inventory to cloud VDR discovery"
```

---

### Task 4: Renderer — assignment plan JSON → `vdr-cloud.yaml`

**Files:**
- Create: `skills/generate-cloud-vdr-config/scripts/render_cloud_config.py`
- Test: `tests/test_render_cloud_config.py`

**Interfaces:**
- Consumes: assignment-plan JSON (shape in "Shared data shapes").
- Produces: `render(plan: dict) -> str` (deterministic YAML text) and CLI `--plan FILE --output FILE`. Task 5 re-renders and byte-compares, so rendering must be a pure function of the plan JSON.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_render_cloud_config.py
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (REPO_ROOT / "skills" / "generate-cloud-vdr-config"
          / "scripts" / "render_cloud_config.py")


def load():
    spec = importlib.util.spec_from_file_location("render_cloud_config", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_plan():
    return {
        "defaults": {
            "class": {"value": "C", "confidence": "high",
                       "evidence": "operator-confirmed", "manualReview": []},
            "multiAgency": {"value": "false", "confidence": "high",
                             "evidence": "operator-confirmed", "manualReview": []},
            "securityImpactProfile": None,
        },
        "archetypes": {},
        "scopes": [{
            "provider": "gcp", "project": "acme-prod",
            "class": {"value": "C", "confidence": "high",
                       "evidence": "operator-confirmed", "manualReview": []},
            "multiAgency": {"value": "false", "confidence": "high",
                             "evidence": "operator-confirmed", "manualReview": []},
            "securityImpactProfile": None,
            "nameRules": [{
                "type": "storage.googleapis.com/Bucket",
                "match": "gcf-sources-*",
                "securityImpactProfile":
                    "service-content.disposable-state.deferrable-work",
                "multiAgency": None, "region": None, "matchTags": None,
                "confidence": "medium",
                "builtinPattern": "gcp-cloudfunctions-staging",
                "evidence": "provider-created transient artifact store",
                "manualReview": ["verify staged contents are non-sensitive"],
            }],
            "tagRules": [], "networkRules": [], "typeRules": [],
        }],
    }


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load()

    def test_render_structure_and_comments(self):
        text = self.mod.render(minimal_plan())
        self.assertIn("apiVersion: vdr.fedramp.io/v1alpha1", text)
        self.assertIn("kind: CloudResourceScoringConfig", text)
        self.assertIn('class: "C"', text)
        self.assertIn('multiAgency: "false"', text)
        self.assertIn("# builtin-pattern: gcp-cloudfunctions-staging", text)
        self.assertIn("# confidence: medium", text)
        self.assertIn("# manual-review: verify staged contents are non-sensitive",
                      text)
        self.assertIn('match: "gcf-sources-*"', text)
        # comment lines sit immediately above the rule entry
        lines = text.splitlines()
        rule_idx = next(i for i, l in enumerate(lines) if "match:" in l and "gcf" in l)
        self.assertTrue(any("# confidence: medium" in l
                            for l in lines[rule_idx - 4:rule_idx]))

    def test_render_is_deterministic(self):
        self.assertEqual(self.mod.render(minimal_plan()),
                         self.mod.render(minimal_plan()))

    def test_high_confidence_needs_no_manual_review_but_medium_does(self):
        plan = minimal_plan()
        plan["scopes"][0]["nameRules"][0]["manualReview"] = []
        with self.assertRaises(ValueError):
            self.mod.render(plan)

    def test_omits_empty_rule_families_and_archetypes(self):
        text = self.mod.render(minimal_plan())
        self.assertNotIn("tagRules", text)
        self.assertNotIn("archetypes", text)
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_render_cloud_config -v` — Expected: FAIL (file not found).

- [ ] **Step 3: Implement the renderer**

Pure string assembly (no YAML library). Layout, in order:

```
# Central cloud-resource scoring assignment surface for trivy-plugin-vdr.
# PROPOSED INTEGRATION CONTRACT: no current scanner consumes this document.
apiVersion: vdr.fedramp.io/v1alpha1
kind: CloudResourceScoringConfig
defaults:
  # confidence: <level> | <evidence>
  class: "C"
  # confidence: <level> | <evidence>
  multiAgency: "false"
scopes:
  - provider: gcp
    project: acme-prod
    # confidence: high | operator-confirmed
    class: "C"
    ...
    nameRules:
      # builtin-pattern: gcp-cloudfunctions-staging
      # confidence: medium | provider-created transient artifact store
      # manual-review: verify staged contents are non-sensitive
      - {type: storage.googleapis.com/Bucket, match: "gcf-sources-*", securityImpactProfile: service-content.disposable-state.deferrable-work}
```

Rules:
- Every attested value (`class`, `multiAgency` at defaults/scope level; each rule) gets `# confidence: <level> | <evidence>` immediately above; each `manualReview` entry becomes its own `# manual-review:` line. Raise `ValueError` if a non-high confidence item has an empty `manualReview` list, or if confidence is not `high|medium|low`.
- Rule entries render as single-line flow maps `- {key: value, ...}` in fixed key order: `type`, `match`, `matchTags`, `network`, `subnet`, `region`, `securityImpactProfile`, `multiAgency`. Omit `None` fields. Quote values containing `*` or spaces; quote `multiAgency` values always; leave dotted traces/types unquoted (they contain no YAML-special characters).
- `matchTags` renders inline as `matchTags: {key: "value"}` with keys sorted.
- Omit empty rule families, empty `archetypes`, and null scope/defaults `securityImpactProfile`. Non-empty `archetypes` render as `name: {description..., cr/ir/ar}` matching the `scoring.yaml` archetype shape.
- Scope key: `project:` for gcp, `account: "<id>"` (quoted — account IDs are digit strings) for aws.
- `main()`: `--plan FILE`, `--output FILE` (default stdout); read JSON, print `render(plan)`.

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest tests.test_render_cloud_config -v` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skills/generate-cloud-vdr-config/scripts/render_cloud_config.py tests/test_render_cloud_config.py
git commit -m "Add deterministic vdr-cloud.yaml renderer"
```

---

### Task 5: Validator — resolution replay, accounting, confidence report

**Files:**
- Create: `skills/generate-cloud-vdr-config/scripts/validate_cloud_config.py`
- Test: `tests/test_validate_cloud_config.py`

**Interfaces:**
- Consumes: plan JSON, inventory JSON, coverage JSON (shapes above); `render()` from Task 4 (imported via `importlib` from the sibling script path); `classify()` + named-archetype resolution reusing the approach in `encode_vdr_metadata.py` (import `reason_codes.py` from `skills/generate-vdr-configmap/scripts/`, parse named profiles from `archetype-guide.md`).
- Produces:
  - `resolve(resource: dict, scope_plan: dict, defaults: dict) -> dict` returning `{"securityImpactProfile": (value, source), "multiAgency": (value, source), "class": (value, source)}` where `source` is `tag-override`, `nameRules[i]`, `tagRules[i]`, `networkRules[i]`, `typeRules[i]`, `scope-default`, `global-default`, or `unresolved`.
  - `validate(plan, inventory, coverage, rendered_text) -> list[str]` (error strings; empty = pass).
  - `confidence_report(plan, coverage) -> str`.
  - CLI: `--plan F --inventory F --coverage F --rendered F`; prints the confidence report; exits 1 when `validate` returns errors, printing each.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_validate_cloud_config.py
import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL = REPO_ROOT / "skills" / "generate-cloud-vdr-config"


def load(stem):
    path = SKILL / "scripts" / f"{stem}.py"
    spec = importlib.util.spec_from_file_location(stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resource(identifier="gcf-sources-42", rtype="storage.googleapis.com/Bucket",
             tags=None, vdr=None, network=None):
    return {"type": rtype, "identifier": identifier, "region": "us-central1",
            "network": network, "subnet": None, "tags": tags or {},
            "vdrTags": vdr or {}, "builtinPatterns": []}


def rule(**kw):
    base = {"type": None, "match": None, "matchTags": None, "network": None,
            "subnet": None, "region": None, "securityImpactProfile": None,
            "multiAgency": None, "confidence": "high", "builtinPattern": None,
            "evidence": "operator attested", "manualReview": []}
    base.update(kw)
    return base


def scope_plan(**families):
    plan = {"provider": "gcp", "project": "acme-prod",
            "class": {"value": "C", "confidence": "high",
                       "evidence": "e", "manualReview": []},
            "multiAgency": {"value": "false", "confidence": "high",
                             "evidence": "e", "manualReview": []},
            "securityImpactProfile": None,
            "nameRules": [], "tagRules": [], "networkRules": [], "typeRules": []}
    plan.update(families)
    return plan


DEFAULTS = {"class": {"value": "C", "confidence": "high", "evidence": "e",
                       "manualReview": []},
            "multiAgency": {"value": "false", "confidence": "high",
                             "evidence": "e", "manualReview": []},
            "securityImpactProfile": None}


class ResolveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load("validate_cloud_config")

    def test_family_precedence_name_beats_tag(self):
        sp = scope_plan(
            nameRules=[rule(type="storage.googleapis.com/Bucket",
                            match="gcf-*", securityImpactProfile="cr-l_ir-l_ar-l")],
            tagRules=[rule(matchTags={"env": "prod"},
                           securityImpactProfile="cr-h_ir-h_ar-h")])
        res = self.mod.resolve(resource(tags={"env": "prod"}), sp, DEFAULTS)
        self.assertEqual(("cr-l_ir-l_ar-l", "nameRules[0]"),
                         res["securityImpactProfile"])

    def test_tag_override_beats_rules(self):
        sp = scope_plan(nameRules=[rule(match="gcf-*",
                                        securityImpactProfile="cr-l_ir-l_ar-l")])
        res = self.mod.resolve(
            resource(vdr={"vdr.fedramp.io/security-impact-profile":
                          "cr-m_ir-m_ar-m"}), sp, DEFAULTS)
        self.assertEqual(("cr-m_ir-m_ar-m", "tag-override"),
                         res["securityImpactProfile"])

    def test_attributes_resolve_independently(self):
        sp = scope_plan(
            nameRules=[rule(match="gcf-sources-42", multiAgency="true")],
            typeRules=[rule(type="storage.googleapis.com/Bucket",
                            securityImpactProfile="cr-l_ir-l_ar-l")])
        res = self.mod.resolve(resource(), sp, DEFAULTS)
        self.assertEqual(("true", "nameRules[0]"), res["multiAgency"])
        self.assertEqual(("cr-l_ir-l_ar-l", "typeRules[0]"),
                         res["securityImpactProfile"])

    def test_network_rule_requires_network_and_unmatched_is_unresolved(self):
        sp = scope_plan(networkRules=[rule(network="prod-vpc",
                                           securityImpactProfile="cr-h_ir-h_ar-h")])
        bucket = self.mod.resolve(resource(), sp, DEFAULTS)  # no network
        self.assertEqual("unresolved", bucket["securityImpactProfile"][1])
        vm = self.mod.resolve(
            resource(identifier="web-1", rtype="compute.googleapis.com/Instance",
                     network="prod-vpc"), sp, DEFAULTS)
        self.assertEqual("networkRules[0]", vm["securityImpactProfile"][1])

    def test_multi_agency_falls_to_scope_then_global(self):
        res = self.mod.resolve(resource(), scope_plan(), DEFAULTS)
        self.assertEqual(("false", "scope-default"), res["multiAgency"])
        self.assertEqual(("C", "scope-default"), res["class"])


class ValidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load("validate_cloud_config")
        cls.render = load("render_cloud_config").render

    def build(self):
        sp = scope_plan(nameRules=[rule(
            type="storage.googleapis.com/Bucket", match="gcf-sources-*",
            securityImpactProfile="service-content.disposable-state.deferrable-work",
            confidence="medium", builtinPattern="gcp-cloudfunctions-staging",
            evidence="provider-created transient artifact store",
            manualReview=["verify contents"])])
        plan = {"defaults": DEFAULTS, "archetypes": {}, "scopes": [sp]}
        inventory = {"scopes": [{"provider": "gcp", "project": "acme-prod",
                                  "provenance": {}, "resources": [resource()],
                                  "tagSummary": {}, "warnings": []}],
                     "summary": {"scopeCount": 1, "resourceCount": 1,
                                  "byType": {"storage.googleapis.com/Bucket": 1}}}
        coverage = {"scopes": ["gcp/acme-prod"], "inventoryTotal": 1,
                    "assignments": [{
                        "scope": "gcp/acme-prod",
                        "type": "storage.googleapis.com/Bucket",
                        "identifier": "gcf-sources-42",
                        "securityImpactProfile":
                            "service-content.disposable-state.deferrable-work",
                        "derivationMethod": "decision-trace", "vector": "M/L/L",
                        "resolutionSource": "nameRules[0]",
                        "multiAgency": "false",
                        "multiAgencySource": "scope-default",
                        "status": "builtin-pattern", "confidence": "medium",
                        "evidence": "provider-created transient artifact store",
                        "assumptions": [],
                        "manualReview": ["verify contents"]}],
                    "configurationAssumptions": [],
                    "summary": {"byScope": {"gcp/acme-prod": 1},
                                 "byFamily": {"nameRules": 1},
                                 "byStatus": {"builtin-pattern": 1},
                                 "byConfidence": {"medium": 1}}}
        return plan, inventory, coverage

    def test_clean_document_passes(self):
        plan, inventory, coverage = self.build()
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertEqual([], errors)

    def test_invalid_trace_fails(self):
        plan, inventory, coverage = self.build()
        plan["scopes"][0]["nameRules"][0]["securityImpactProfile"] = \
            "made-up.reasons.here"
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("made-up" in e for e in errors))

    def test_unresolved_resource_fails(self):
        plan, inventory, coverage = self.build()
        inventory["scopes"][0]["resources"].append(
            resource(identifier="mystery-bucket"))
        inventory["summary"]["resourceCount"] = 2
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("mystery-bucket" in e and "unresolved" in e
                            for e in errors))

    def test_zero_match_rule_fails(self):
        plan, inventory, coverage = self.build()
        plan["scopes"][0]["typeRules"].append(rule(
            type="sqladmin.googleapis.com/Instance",
            securityImpactProfile="cr-m_ir-m_ar-m"))
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("matches no inventoried resource" in e
                            for e in errors))

    def test_shadowed_rule_fails(self):
        plan, inventory, coverage = self.build()
        plan["scopes"][0]["nameRules"].append(rule(
            type="storage.googleapis.com/Bucket", match="gcf-sources-42",
            securityImpactProfile="cr-l_ir-l_ar-l"))
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("shadow" in e for e in errors))

    def test_coverage_accounting_mismatch_fails(self):
        plan, inventory, coverage = self.build()
        coverage["assignments"] = []
        coverage["inventoryTotal"] = 0
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertTrue(any("inventory equation" in e for e in errors))

    def test_rendered_drift_fails(self):
        plan, inventory, coverage = self.build()
        errors = self.mod.validate(plan, inventory, coverage,
                                   self.render(plan) + "\n# edited\n")
        self.assertTrue(any("rendered" in e for e in errors))

    def test_conflicting_tag_override_reported(self):
        plan, inventory, coverage = self.build()
        inventory["scopes"][0]["resources"][0]["vdrTags"] = {
            "vdr.fedramp.io/security-impact-profile": "cr-h_ir-h_ar-h"}
        coverage["assignments"][0]["resolutionSource"] = "tag-override"
        coverage["assignments"][0]["securityImpactProfile"] = "cr-h_ir-h_ar-h"
        coverage["assignments"][0]["derivationMethod"] = "direct-vector"
        coverage["assignments"][0]["vector"] = "H/H/H"
        errors = self.mod.validate(plan, inventory, coverage, self.render(plan))
        self.assertEqual([], errors)  # override is legal, not an error
        report = self.mod.confidence_report(plan, coverage)
        self.assertIn("tag-override", report)

    def test_confidence_report_lists_medium_and_none(self):
        plan, inventory, coverage = self.build()
        report = self.mod.confidence_report(plan, coverage)
        self.assertIn("gcf-sources-42", report)
        self.assertIn("verify contents", report)
        coverage["assignments"][0]["confidence"] = "high"
        coverage["assignments"][0]["status"] = "operator-confirmed"
        coverage["assignments"][0]["manualReview"] = []
        plan["scopes"][0]["nameRules"][0]["confidence"] = "high"
        plan["scopes"][0]["nameRules"][0]["manualReview"] = []
        report = self.mod.confidence_report(plan, coverage)
        self.assertIn("none", report.lower())
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m unittest tests.test_validate_cloud_config -v` — Expected: FAIL (file not found).

- [ ] **Step 3: Implement the validator**

Core pieces:

```python
FAMILIES = ("nameRules", "tagRules", "networkRules", "typeRules")
SIP_TAG = "vdr.fedramp.io/security-impact-profile"
MA_TAG = "vdr.fedramp.io/multi-agency"
CLASS_TAG = "vdr.fedramp.io/class"


def rule_matches(rule, res, family):
    if rule.get("type") and rule["type"] != res["type"]:
        return False
    if rule.get("region") and not fnmatch.fnmatchcase(res.get("region") or "",
                                                      rule["region"]):
        return False
    if family == "nameRules" and not fnmatch.fnmatchcase(res["identifier"],
                                                         rule["match"]):
        return False
    if rule.get("matchTags"):
        tags = res.get("tags") or {}
        if not all(key in tags and fnmatch.fnmatchcase(str(tags[key]), str(val))
                   for key, val in rule["matchTags"].items()):
            return False
    if family == "networkRules":
        if not res.get("network"):
            return False
        if not fnmatch.fnmatchcase(res["network"], rule["network"]):
            return False
        if rule.get("subnet") and not fnmatch.fnmatchcase(res.get("subnet") or "",
                                                          rule["subnet"]):
            return False
    if family == "tagRules" and not rule.get("matchTags"):
        return False
    if family == "typeRules" and not rule.get("type"):
        return False
    return True


def resolve(res, scope_plan, defaults):
    out = {}
    vdr = res.get("vdrTags") or {}
    sip = (vdr[SIP_TAG], "tag-override") if SIP_TAG in vdr else None
    ma = (vdr[MA_TAG], "tag-override") if MA_TAG in vdr else None
    cls = (vdr[CLASS_TAG], "tag-override") if CLASS_TAG in vdr else None
    for family in FAMILIES:
        for index, rule in enumerate(scope_plan.get(family) or []):
            if (sip and ma) or not rule_matches(rule, res, family):
                continue
            source = "%s[%d]" % (family, index)
            if sip is None and rule.get("securityImpactProfile"):
                sip = (rule["securityImpactProfile"], source)
            if ma is None and rule.get("multiAgency") is not None:
                ma = (rule["multiAgency"], source)
    if sip is None and scope_plan.get("securityImpactProfile"):
        sip = (scope_plan["securityImpactProfile"], "scope-default")
    if sip is None and defaults.get("securityImpactProfile"):
        sip = (defaults["securityImpactProfile"], "global-default")
    if ma is None:
        ma = (scope_plan["multiAgency"]["value"], "scope-default") \
            if scope_plan.get("multiAgency") else \
            (defaults["multiAgency"]["value"], "global-default")
    if cls is None:
        cls = (scope_plan["class"]["value"], "scope-default") \
            if scope_plan.get("class") else \
            (defaults["class"]["value"], "global-default")
    out["securityImpactProfile"] = sip or (None, "unresolved")
    out["multiAgency"] = ma
    out["class"] = cls
    return out
```

`validate(plan, inventory, coverage, rendered_text)` collects error strings for:
1. every rule's SIP value validity — decision trace via imported `classify` (reuse `encode_vdr_metadata.py`'s `resolve_profile` approach: direct-vector regex `cr-([lmh])_ir-([lmh])_ar-([lmh])`, else named archetype from `archetype-guide.md` table, else trace via `classify`); include the offending value in the message;
2. rule shape: required family fields present (`match` for nameRules, `matchTags` for tagRules, `network` for networkRules, `type` for typeRules); at least one of `securityImpactProfile`/`multiAgency` set; confidence valid; non-high confidence with empty `manualReview`;
3. `networkRules` whose `type` names a non-network-attachable type (`storage.googleapis.com/Bucket`, `AWS::S3::Bucket`, `bigquery.googleapis.com/Dataset` — module constant `GLOBAL_TYPES`);
4. resolution replay: for each inventory resource in its matching plan scope (match scopes by provider+project/account; a scope in inventory missing from the plan, or vice versa, is an error): `unresolved` SIP → error `"<identifier> unresolved: no rule, scope default, or global default assigns a securityImpactProfile"`;
5. zero-match rules: any plan rule matched by no inventory resource → `"<family>[<i>] in <scope> matches no inventoried resource"` (the agent relays operator-attested forward-looking rules by removing them or getting attestation; the script stays strict);
6. shadowed rules: within a family, a later rule whose matched-resource set is a subset of an earlier rule's matched set (both setting the same attribute) → `"...shadowed by..."` error containing the word `shadow`;
7. inventory equation: coverage `inventoryTotal` == inventory `summary.resourceCount` == len(assignments); every inventory resource appears exactly once in assignments (keyed by scope+type+identifier); mismatch messages contain `"inventory equation"`;
8. per-assignment cross-check: `resolutionSource` and resolved SIP from replay must equal the coverage entry's values; every non-high entry has ≥1 `manualReview` item; `vector` matches the mechanically derived vector;
9. rendered drift: `render(plan) != rendered_text` → error containing `"rendered vdr-cloud.yaml does not match the plan"`.

`confidence_report(plan, coverage)` prints every medium/low assignment and configuration assumption (value, evidence, manual-review actions), every `tag-override` resolution (as override provenance), and the literal line `manual-review items: none` when everything is high-confidence with no assumptions.

`main()` wires `--plan/--inventory/--coverage/--rendered`, prints report to stdout, errors to stderr, exit 1 on any error.

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest tests.test_validate_cloud_config -v` — Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `python3 -m unittest discover -s tests -v` — Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add skills/generate-cloud-vdr-config/scripts/validate_cloud_config.py tests/test_validate_cloud_config.py
git commit -m "Add cloud config validator with resolution replay and confidence report"
```

---

### Task 6: SKILL.md, references, example asset, README

**Files:**
- Create: `skills/generate-cloud-vdr-config/SKILL.md`
- Create: `skills/generate-cloud-vdr-config/references/cloud-config-schema.md`
- Create: `skills/generate-cloud-vdr-config/references/managed-resource-patterns.md`
- Create: `skills/generate-cloud-vdr-config/assets/vdr-cloud.example.yaml`
- Modify: `README.md` (add the skill to "The skills" section and the Requirements table)

**Interfaces:**
- Consumes: everything above; command examples must use the exact CLIs implemented in Tasks 2-5.

- [ ] **Step 1: Write `references/cloud-config-schema.md`**

Transcribe from the spec (`docs/superpowers/specs/2026-08-04-cloud-resource-scoring-config-design.md`): the full document schema with the annotated example, the 8-tier precedence list, independent per-attribute resolution, rule-family field table (required/optional fields per family, exact-match `type`, `fnmatch` globs elsewhere), the primary-identifier table (GCS bucket name; Cloud SQL instance name; GCE instance name; BigQuery dataset id; S3 bucket name; EC2 **instance ID** — Name-tag matching goes through `tagRules`; RDS DB identifier), canonical-value rules (no provider encodings inside the document), comment conventions, and the fail-loud stance on scope/global SIP defaults. State plainly: this document is a proposed integration contract; no current scanner consumes it.

- [ ] **Step 2: Write `references/managed-resource-patterns.md`**

One section per catalog entry: what creates the resource, why tagging control is limited, the default trace `service-content.disposable-state.deferrable-work` → M/L/L with the CR:M failsafe rationale (sensitive material can be embedded in code/templates), the attest-down path (operator may replace with a direct vector after verifying contents), and the medium-confidence cap. State that matched patterns are always materialized as explicit commented rules, never silently assumed.

- [ ] **Step 3: Write `SKILL.md`**

Frontmatter description (single paragraph, mirroring sibling skills): generate or update the central `vdr-cloud.yaml` CloudResourceScoringConfig from read-only gcloud/aws discovery of CIS-addressed cloud resources; name/tag/network/type rule matching; materialized managed-resource patterns; coverage ledger; never applies anything. Body sections mirroring `generate-vdr-configmap/SKILL.md`:
1. **Ground rules** — read-only verbs; write only under `./vdr-cloud-output/`; artifacts are a proposed integration contract (say so in every handoff); best-effort generation with fail-closed `D`/`"true"` provisional defaults; existing `vdr.fedramp.io/*` tags are evidence, not attestation, unless reconfirmed; never write secret-bearing config into artifacts.
2. **Workflow step 1: establish scopes** — single vs multi-scope question; AWS profile→account mapping confirmed via `aws sts get-caller-identity --profile <p>`; GCP project selection via `gcloud projects list`; pin `--profile`/`--project` everywhere; failed scopes are excluded and reported, never partially emitted.
3. **Step 2: inventory** — exact commands: `python3 <skill-dir>/scripts/inventory_cloud_resources.py --provider gcp --project <p> --output ./vdr-cloud-output/scope-gcp-<p>.json` (and the aws/`--merge` forms); preserve exact merged JSON as `resource-inventory.json`; degraded-inventory warnings are surfaced, never silent.
4. **Step 3: mine tags and patterns** — use `tagSummary` to propose `tagRules` on coherent operator taxonomies; report `vdrTags` overrides; pattern matches are pre-classified at medium confidence with the catalog's manual-review notes.
5. **Step 4: interview** — reuse the archetype guide's five-question interview per coherent group (read `../generate-vdr-configmap/references/archetype-guide.md` completely); environment names never establish impact; HA never lowers AR; confidence describes evidence quality, never lowers CR/IR/AR.
6. **Step 5: author the assignment plan** — write `./vdr-cloud-output/assignment-plan.json` (shape documented in `references/cloud-config-schema.md`); prefer `nameRules` with exact identifiers; `tagRules` only over verified-coherent taxonomies; `networkRules` only when every relevant attached resource shares the profile; fail-loud over broad defaults.
7. **Step 6: emit and validate** — `render_cloud_config.py --plan ... --output ./vdr-cloud-output/vdr-cloud.yaml`; author `assignment-coverage.json`; run `validate_cloud_config.py --plan ... --inventory ... --coverage ... --rendered ...`; treat nonzero exit as failure; run the proprietary-term deny-list scan over all generated files when the user supplies one; keep `skills/` and `.agents/skills/` byte-identical.
8. **Handoff** — totals by scope/status/confidence, repeat the manual-review list in the terminal, state the proposed-contract caveat, tell the operator to review and version the artifacts; re-run after estate/Class/scope changes.

- [ ] **Step 4: Generate `assets/vdr-cloud.example.yaml`**

Author a small fictional two-scope plan JSON (one GCP project with a PHI bucket nameRule, a `data-class: phi` tagRule, a Cloud SQL networkRule, a GCE typeRule, and one `gcf-sources-*` builtin-pattern rule; one AWS account with an S3 nameRule and `cf-templates-*` pattern rule), render it with `render_cloud_config.py`, and save the output as the example. Add a header comment naming it fictional.

- [ ] **Step 5: Update `README.md`**

Add a `### generate-cloud-vdr-config → the central vdr-cloud.yaml (proposed contract)` subsection after `generate-vdr-configmap`, summarizing: central assignment surface for CIS-addressed GCP/AWS resources, rule families, tag overrides demoted to exceptions, materialized managed-resource patterns, proposed-integration-contract caveat. Add a Requirements row: `gcloud` / `aws` CLIs (authenticated, read-only) for `generate-cloud-vdr-config` only.

- [ ] **Step 6: Verify example renders cleanly and suite passes**

Run: `python3 skills/generate-cloud-vdr-config/scripts/render_cloud_config.py --plan /tmp/example-plan.json` and `python3 -m unittest discover -s tests -v` — Expected: rendered output matches the committed asset; all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add skills/generate-cloud-vdr-config README.md
git commit -m "Add generate-cloud-vdr-config skill docs, schema reference, and example"
```

---

### Task 7: Sync `.agents/skills/` copy and final verification

**Files:**
- Create: `.agents/skills/generate-cloud-vdr-config/` (byte-identical copy)

- [ ] **Step 1: Copy the skill**

```bash
rm -rf .agents/skills/generate-cloud-vdr-config
cp -R skills/generate-cloud-vdr-config .agents/skills/generate-cloud-vdr-config
find .agents/skills/generate-cloud-vdr-config -name __pycache__ -type d -exec rm -rf {} +
```

- [ ] **Step 2: Verify byte-identical**

Run: `diff -r skills/generate-cloud-vdr-config .agents/skills/generate-cloud-vdr-config`
Expected: no output.

- [ ] **Step 3: Full suite**

Run: `python3 -m unittest discover -s tests -v` — Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add .agents/skills/generate-cloud-vdr-config
git commit -m "Mirror generate-cloud-vdr-config into .agents skills"
```
