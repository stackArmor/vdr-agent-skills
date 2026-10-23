# VDR metadata contract

This page defines the metadata an integration must provide to classify assets
for FedRAMP VDR/VER scoring. The agent skills can help collect and assign the
metadata, but an integration can produce it directly if it follows this
contract.

## Asset metadata

| Field | Values | Purpose |
|---|---|---|
| `class` | `A`, `B`, `C`, or `D` | FedRAMP Certification Class: Ready, Low, Moderate, or High. |
| `multiAgency` | `true` or `false` | Whether compromise of the asset could affect more than one agency. |
| `securityImpactProfile` | A direct CR/IR/AR vector, a governed decision trace, or a configured named archetype | Describes the asset's confidentiality, integrity, and availability requirements independently. |

These fields are independent inputs. Agency scope does not determine the
security-impact profile, and the profile does not determine agency scope.

## Agency scope and PAIN

Set `multiAgency: true` when the asset is part of shared multi-tenant
infrastructure and a compromise could cross agency boundaries. Set it to
`false` for a dedicated deployment whose compromise is limited to one agency.
For shared services, evaluate the service's actual tenant reach rather than
assuming that every asset inherits the customer-facing deployment model.

The scoring consumer uses the multi-agency value when assigning the PAIN tier;
it can raise the tier when a finding has cross-agency impact. The FedRAMP Class
then combines with that tier and reachability-based vulnerability status to
determine the remediation deadline. Missing classification is handled
conservatively by the plugin's fail-safe.

## Security-impact profile taxonomy

The profile carries three independently selected dimensions:

- **CR (Confidentiality Requirement):** impact if information is disclosed.
- **IR (Integrity Requirement):** impact if trusted information or actions are changed.
- **AR (Availability Requirement):** impact if the asset is unavailable.

Each dimension is `L`, `M`, or `H`. The preferred human-auditable form is a
three-part decision trace:

```text
<disclosure-reason>.<trusted-change-reason>.<dependency-reason>
```

For example, `privileged-access.foundation-control.recovery-critical`
resolves to `CR=H`, `IR=H`, `AR=H`. Use only reasons in the governed registries
in [`archetype-guide.md`](../skills/generate-k8s-vdr-configmap/references/archetype-guide.md).
Do not add new reason tokens without updating the registry and its validator.

The runtime also accepts a direct vector such as `cr-h_ir-m_ar-l`. A named
archetype is valid only when that catalog entry is configured for the
consumer. Do not transmit a scalar asset-value field in place of the profile;
translate it to an equal-dimension vector and record that the derivation loses
independent CR/IR/AR rationale.

## Transport

Use the transport appropriate to the asset and consumer:

- Kubernetes: `vdr.fedramp.io/class`, `vdr.fedramp.io/multi-agency`, and
  `vdr.fedramp.io/security-impact-profile` labels, or equivalent assignments
  in the `vdr-fedramp` ConfigMap.
- Cloud resources: `class`, `multiAgency`, and
  `securityImpactProfile` in the `vdr-cloud.yaml` assignment document.
- Terraform-managed assets: provider-native labels or tags using the canonical
  `vdr.fedramp.io/*` keys where the resource supports them.

Boolean values are represented as quoted strings in Kubernetes labels and the
cloud YAML contract (`"true"` / `"false"`). Preserve the same meaning when an
integration normalizes them internally.

## Example

```yaml
class: "C"
multiAgency: "true"
securityImpactProfile: "privileged-access.foundation-control.recovery-critical"
```

This example describes a FedRAMP Moderate asset in a shared, multi-agency
environment with high confidentiality, integrity, and availability
requirements. Operators should attest the agency scope and profile using
system architecture and impact evidence; names or environment labels alone
are not sufficient evidence.

## Related references

- [Kubernetes ConfigMap workflow](../skills/generate-k8s-vdr-configmap/SKILL.md)
- [Cloud assignment format](../skills/generate-cloud-vdr-config/references/cloud-config-schema.md)
- [Security-impact profile taxonomy and examples](../skills/generate-k8s-vdr-configmap/references/archetype-guide.md)
- [VDR scoring consumer](https://github.com/stackArmor/trivy-plugin-vdr)
