#!/usr/bin/env python3
"""capture_dataflow.py -- staged, read-only Kubernetes dataflow capture for trivy-plugin-vdr.

Produces, under --output-dir (default ./vdr-dataflow-output):
  bundle.json      full capture bundle (stage verdicts, inventory, edges) for agentic review
  configmap.yaml   ConfigMap vdr-dataflow (namespace fedramp-vdr-trivy), data key dataflow.yaml
  diagrams/*.mmd   one Mermaid flowchart per namespace containing >=1 internet-exposed workload

Hard guarantees:
  - kubectl is invoked with read-only verbs only (get / config view-style reads).
    NEVER exec, apply, create, patch, delete. Enforced by _run_kubectl().
  - Secret values may be parsed in memory for URL/host extraction, but outputs and
    evidence contain at most scheme+host+port -- never credential material, never
    raw secret values.
  - Nothing is written to the cluster. The operator reviews configmap.yaml and applies
    it manually or via GitOps.

Staged pipeline (each stage records a sufficiency verdict: complete | partial | absent):
  Stage 0 (always)   entry-point inventory: Ingress, Gateway API, Service type=LoadBalancer
  Stage 1            NetworkPolicy (+ CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy)
  Stage 2            service-mesh authorization/config (Istio, Linkerd)
  Stage 3 (optional) observed flows (--flows-file, --mesh-metrics-file); ENRICH ONLY --
                     absence of an observed flow never prunes an edge
  Stage 4            declared-config extraction (env / envFrom / ConfigMap mounts / args)

Once a stage yields a COMPLETE permitted-flow map, later source stages are skipped
(Stage 0 always runs; Stage 3 runs whenever its input files are supplied). --all-stages
forces every stage. Stage 4 and Stage 3 can never be "complete" on their own: declared
config cannot see image-baked configuration, and observation cannot prove absence --
completeness of declared topology comes only from operator attestation (--merge).

python3, stdlib only. Requires an authenticated kubectl on PATH.
"""

import argparse
import base64
import datetime
import ipaddress
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlparse

VERSION = "0.1.0"
GENERATOR = f"capture-dataflow/{VERSION} (trivy-plugin-vdr-skills)"
SCHEMA_VERSION = "v1alpha1"
CONFIGMAP_NAME = "vdr-dataflow"
CONFIGMAP_NAMESPACE = "fedramp-vdr-trivy"

# Namespaces excluded by default under --all-namespaces (prefix match).
SYSTEM_NS_PREFIXES = (
    "kube-", "gke-", "gmp-", "gatekeeper-", "config-management",
    "resource-group", "cnrm-", "asm-", "istio-operator",
)

WORKLOAD_KINDS = (
    ("deployments", "deployment"),
    ("statefulsets", "statefulset"),
    ("daemonsets", "daemonset"),
    ("cronjobs", "cronjob"),
)

# Well-known datastore/broker ports -> protocol hint (also drives green cylinders in Mermaid).
DATASTORE_PORTS = {
    5432: "postgres", 3306: "mysql", 6379: "redis", 9092: "kafka",
    2181: "zookeeper", 8081: "schema-registry", 27017: "mongodb", 9200: "elasticsearch",
    9300: "elasticsearch", 5672: "amqp", 5671: "amqps", 11211: "memcached",
    9042: "cassandra", 1433: "mssql", 1521: "oracle", 8086: "influxdb",
    26257: "cockroachdb", 5984: "couchdb", 8529: "arangodb",
}

SCHEME_DEFAULT_PORTS = {
    "http": 80, "https": 443, "postgres": 5432, "postgresql": 5432, "mysql": 3306,
    "redis": 6379, "rediss": 6379, "mongodb": 27017, "amqp": 5672, "amqps": 5671,
    "kafka": 9092, "ldap": 389, "ldaps": 636, "grpc": 443, "nats": 4222, "ftp": 21,
}

# Hosts never worth recording as unresolved (loopback, cloud metadata, apiserver).
IGNORE_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "metadata.google.internal", "169.254.169.254",
}

URL_RE = re.compile(r'\b([a-z][a-z0-9+.-]{1,15})://([^\s"\'<>]{3,200})', re.I)
HOSTPORT_RE = re.compile(r'\b([a-z0-9]([a-z0-9.-]{1,80}[a-z0-9])?):(\d{2,5})\b', re.I)
ENV_EXPAND_RE = re.compile(r'\$\((\w+)\)')


def log(msg):
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# kubectl (read-only, enforced)
# ---------------------------------------------------------------------------

_KUBECTL_READONLY_VERBS = ("get", "config")


def _run_kubectl(argv):
    """Single kubectl entry point. Refuses anything but read-only verbs."""
    if not argv or argv[0] not in _KUBECTL_READONLY_VERBS:
        raise RuntimeError(f"refusing non-read-only kubectl verb: {argv[:1]}")
    if argv[0] == "config" and (len(argv) < 2 or argv[1] not in ("current-context", "view")):
        raise RuntimeError(f"refusing kubectl config subcommand: {argv[:2]}")
    return subprocess.run(["kubectl"] + argv, capture_output=True, text=True)


def kget(resource, ns=None, name=None, all_ns=False):
    """kubectl get ... -o json. Returns (parsed_or_None, error_summary_or_None)."""
    args = ["get", resource]
    if name:
        args.append(name)
    if all_ns:
        args.append("-A")
    elif ns:
        args += ["-n", ns]
    args += ["-o", "json"]
    r = _run_kubectl(args)
    if r.returncode != 0:
        err = (r.stderr or "").strip().splitlines()
        return None, (err[0] if err else "kubectl get failed")
    try:
        return json.loads(r.stdout), None
    except json.JSONDecodeError:
        return None, "unparseable kubectl output"


def kitems(resource, ns=None, all_ns=False):
    """List items of a resource; (items, error). Missing CRD/RBAC-denied -> ([], error)."""
    data, err = kget(resource, ns=ns, all_ns=all_ns)
    if data is None:
        return [], err
    return data.get("items", []), None


def current_context():
    r = _run_kubectl(["config", "current-context"])
    return r.stdout.strip() if r.returncode == 0 else "(unknown)"


# ---------------------------------------------------------------------------
# Minimal YAML (emit always; parse used for --merge when PyYAML is absent)
# ---------------------------------------------------------------------------

_PLAIN_SCALAR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./-]*$")


def _yscalar(v):
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    if _PLAIN_SCALAR_RE.match(s) and s.lower() not in ("true", "false", "null", "yes", "no", "on", "off") \
            and not re.fullmatch(r"-?\d+(\.\d+)?", s) \
            and not re.fullmatch(r"\d{4}-\d{2}-\d{2}.*", s):  # keep dates as strings
        return s
    return json.dumps(s)


def emit_yaml(obj, indent=0):
    """Deterministic block-style YAML emitter (2-space indent). Returns list of lines."""
    pad = "  " * indent
    lines = []
    if isinstance(obj, dict):
        if not obj:
            return [pad + "{}"]
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{k}:")
                lines += emit_yaml(v, indent + 1)
            elif isinstance(v, dict):
                lines.append(f"{pad}{k}: {{}}")
            elif isinstance(v, list):
                lines.append(f"{pad}{k}: []")
            else:
                lines.append(f"{pad}{k}: {_yscalar(v)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                sub = emit_yaml(item, indent + 1)
                lines.append(f"{pad}- {sub[0].strip()}")
                lines += sub[1:]
            else:
                lines.append(f"{pad}- {_yscalar(item)}")
    else:
        lines.append(pad + _yscalar(obj))
    return lines


def _coerce_scalar(tok):
    t = tok.strip()
    if t.startswith(('"', "'")) and t.endswith(t[0]) and len(t) >= 2:
        return t[1:-1]
    low = t.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    return t


def _parse_flow(s):
    """Parse inline YAML flow syntax: {k: v, ...} or [a, b]. Best-effort, no nesting of quotes."""
    s = s.strip()

    def split_top(body):
        parts, depth, cur, quote = [], 0, "", None
        for ch in body:
            if quote:
                cur += ch
                if ch == quote:
                    quote = None
                continue
            if ch in "\"'":
                quote = ch
                cur += ch
            elif ch in "{[":
                depth += 1
                cur += ch
            elif ch in "}]":
                depth -= 1
                cur += ch
            elif ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
            else:
                cur += ch
        if cur.strip():
            parts.append(cur)
        return parts

    if s.startswith("{") and s.endswith("}"):
        out = {}
        for part in split_top(s[1:-1]):
            if ":" not in part:
                continue
            k, v = part.split(":", 1)
            out[k.strip().strip("\"'")] = _parse_flow(v)
        return out
    if s.startswith("[") and s.endswith("]"):
        return [_parse_flow(p) for p in split_top(s[1:-1])]
    return _coerce_scalar(s)


def parse_simple_yaml(text):
    """Parse the documented operator-edges.yaml subset: block mappings/sequences with
    2-space-ish indentation, inline {}/[] flow values, quoted scalars, # comments.
    No anchors, no multi-line block scalars, no multi-document streams."""
    try:
        import yaml  # type: ignore  # PyYAML if available; otherwise the subset parser below
        return yaml.safe_load(text)
    except ImportError:
        pass

    rows = []
    for raw in text.splitlines():
        no_comment = re.sub(r'(?<!["\w])#.*$', "", raw) if "#" in raw else raw
        if not no_comment.strip():
            continue
        indent = len(no_comment) - len(no_comment.lstrip(" "))
        rows.append((indent, no_comment.strip()))

    def parse_block(i, indent):
        # Decide mapping vs sequence from the first row at this level.
        seq = rows[i][1].startswith("- ") or rows[i][1] == "-"
        result = [] if seq else {}
        while i < len(rows):
            ind, content = rows[i]
            if ind < indent:
                break
            if ind > indent:
                raise ValueError(f"unexpected indent in merge file near: {content!r}")
            if seq:
                if not (content.startswith("- ") or content == "-"):
                    break
                item = content[1:].strip()
                if not item:  # "-" alone: nested block follows
                    val, i = parse_block(i + 1, rows[i + 1][0]) if i + 1 < len(rows) else (None, i + 1)
                    result.append(val)
                    continue
                if item.startswith(("{", "[")):
                    result.append(_parse_flow(item))
                    i += 1
                elif ":" in item and not item.startswith(('"', "'")):
                    # "- key: value" starts an inline mapping item; fold following deeper rows in.
                    obj, i = parse_inline_map_item(i, ind, item)
                    result.append(obj)
                else:
                    result.append(_coerce_scalar(item))
                    i += 1
            else:
                if content.startswith("- "):
                    break
                if ":" not in content:
                    raise ValueError(f"expected 'key:' in merge file near: {content!r}")
                k, v = content.split(":", 1)
                k, v = k.strip().strip("\"'"), v.strip()
                if v == "":
                    if i + 1 < len(rows) and rows[i + 1][0] > ind:
                        result[k], i = parse_block(i + 1, rows[i + 1][0])
                    else:
                        result[k] = None
                        i += 1
                elif v.startswith(("{", "[")):
                    result[k] = _parse_flow(v)
                    i += 1
                else:
                    result[k] = _coerce_scalar(v)
                    i += 1
        return result, i

    def parse_inline_map_item(i, ind, first):
        """Handle '- key: value' with possible continuation keys indented under it."""
        obj = {}
        k, v = first.split(":", 1)
        v = v.strip()
        if v.startswith(("{", "[")):
            obj[k.strip()] = _parse_flow(v)
        elif v == "":
            obj[k.strip()] = None  # replaced below if a nested block follows
        else:
            obj[k.strip()] = _coerce_scalar(v)
        i += 1
        item_indent = ind + 2  # continuation keys align under the first key
        while i < len(rows) and rows[i][0] >= item_indent and not rows[i][1].startswith("- "):
            sub_ind, content = rows[i]
            if sub_ind != item_indent:
                sub, i = parse_block(i, sub_ind)
                # nested block belongs to the last empty key
                for kk in reversed(list(obj)):
                    if obj[kk] is None:
                        obj[kk] = sub
                        break
                continue
            k2, v2 = content.split(":", 1)
            v2 = v2.strip()
            if v2 == "":
                if i + 1 < len(rows) and rows[i + 1][0] > sub_ind:
                    obj[k2.strip()], i = parse_block(i + 1, rows[i + 1][0])
                    continue
                obj[k2.strip()] = None
            elif v2.startswith(("{", "[")):
                obj[k2.strip()] = _parse_flow(v2)
            else:
                obj[k2.strip()] = _coerce_scalar(v2)
            i += 1
        return obj, i

    if not rows:
        return {}
    val, _ = parse_block(0, rows[0][0])
    return val


# ---------------------------------------------------------------------------
# Selector matching
# ---------------------------------------------------------------------------

def match_selector(selector, labels):
    """Kubernetes label selector semantics. Empty/{} selector matches everything;
    None (field absent) also matches everything for NetworkPolicy podSelector."""
    if not selector:
        return True
    labels = labels or {}
    for k, v in (selector.get("matchLabels") or {}).items():
        if labels.get(k) != v:
            return False
    for expr in (selector.get("matchExpressions") or []):
        key, op, vals = expr.get("key"), expr.get("operator"), expr.get("values") or []
        if op == "In":
            if labels.get(key) not in vals:
                return False
        elif op == "NotIn":
            if labels.get(key) in vals:
                return False
        elif op == "Exists":
            if key not in labels:
                return False
        elif op == "DoesNotExist":
            if key in labels:
                return False
    return True


def strip_cilium_prefixes(match_labels):
    """CiliumNetworkPolicy labels may carry 'k8s:' / 'any:' prefixes."""
    out = {}
    for k, v in (match_labels or {}).items():
        for pfx in ("k8s:", "any:"):
            if k.startswith(pfx):
                k = k[len(pfx):]
        out[k] = v
    return out


# ---------------------------------------------------------------------------
# Cluster inventory
# ---------------------------------------------------------------------------

class Cluster:
    def __init__(self, namespaces):
        self.namespaces = namespaces
        self.ns_labels = {}
        self.workloads = []          # dicts: ns kind name labels podspec sa mesh_enrolled
        self.services = []           # raw service objects (in-scope namespaces)
        self.svc_meta = {}           # (ns, name) -> {ip, ports[{port,name,protocol}], type, selector}
        self.svc_index = {}          # resolvable form -> (ns, name)
        self.bare_names = {}         # bare svc name -> [ns, ...]
        self.cm_cache = {}
        self.secret_cache = {}

    def load(self):
        ns_items, _ = kitems("namespaces")
        for n in ns_items:
            self.ns_labels[n["metadata"]["name"]] = n["metadata"].get("labels", {}) or {}

        all_svcs, err = kitems("services", all_ns=True)
        if err:
            log(f"  ! services list failed: {err}")
        for s in all_svcs:
            ns, name = s["metadata"]["namespace"], s["metadata"]["name"]
            spec = s.get("spec", {})
            ports = [{"port": p.get("port"), "name": p.get("name") or "",
                      "protocol": (p.get("protocol") or "TCP").lower()}
                     for p in spec.get("ports", [])]
            ip = spec.get("clusterIP", "")
            self.svc_meta[(ns, name)] = {
                "ip": ip, "ports": ports, "type": spec.get("type", "ClusterIP"),
                "selector": spec.get("selector") or {},
                "annotations": s["metadata"].get("annotations", {}) or {},
                "status": s.get("status", {}),
            }
            for form in (f"{name}.{ns}.svc.cluster.local", f"{name}.{ns}.svc", f"{name}.{ns}"):
                self.svc_index[form] = (ns, name)
            self.bare_names.setdefault(name, []).append(ns)
            if ip and ip != "None":
                self.svc_index[ip] = (ns, name)
            if ns in self.namespaces:
                self.services.append(s)

        for plural, kind in WORKLOAD_KINDS:
            for ns in self.namespaces:
                items, err = kitems(plural, ns=ns)
                if err and "doesn't have a resource type" not in err:
                    log(f"  ! {plural} in {ns}: {err}")
                for w in items:
                    if kind == "cronjob":
                        tmpl = w["spec"].get("jobTemplate", {}).get("spec", {}).get("template", {})
                    else:
                        tmpl = w["spec"].get("template", {})
                    podspec = tmpl.get("spec", {}) or {}
                    labels = (tmpl.get("metadata", {}) or {}).get("labels", {}) or {}
                    ann = (tmpl.get("metadata", {}) or {}).get("annotations", {}) or {}
                    self.workloads.append({
                        "namespace": ns, "kind": kind, "name": w["metadata"]["name"],
                        "labels": labels, "annotations": ann, "podspec": podspec,
                        "serviceAccount": podspec.get("serviceAccountName", "default"),
                        "mesh_enrolled": self._mesh_enrolled(ns, labels, ann),
                    })

    def _mesh_enrolled(self, ns, labels, annotations):
        nsl = self.ns_labels.get(ns, {})
        if nsl.get("istio-injection") == "enabled" or "istio.io/rev" in nsl:
            if labels.get("sidecar.istio.io/inject") != "false":
                return True
        if labels.get("sidecar.istio.io/inject") == "true" or annotations.get("sidecar.istio.io/inject") == "true":
            return True
        if nsl.get("linkerd.io/inject") == "enabled" or annotations.get("linkerd.io/inject") == "enabled":
            return True
        return False

    def workload_key(self, w):
        return (w["namespace"], w["kind"], w["name"])

    def services_selecting(self, w):
        """Services whose selector matches this workload's pod template labels."""
        out = []
        for (ns, name), meta in self.svc_meta.items():
            if ns != w["namespace"] or not meta["selector"]:
                continue
            if all(w["labels"].get(k) == v for k, v in meta["selector"].items()):
                out.append((ns, name))
        return sorted(out)

    def workloads_for_service(self, ns, name):
        meta = self.svc_meta.get((ns, name))
        if not meta or not meta["selector"]:
            return []
        return [w for w in self.workloads
                if w["namespace"] == ns and all(w["labels"].get(k) == v for k, v in meta["selector"].items())]

    def workloads_matching(self, ns, selector):
        return [w for w in self.workloads if w["namespace"] == ns and match_selector(selector, w["labels"])]

    def get_configmap(self, ns, name):
        if (ns, name) not in self.cm_cache:
            data, _ = kget("configmap", ns=ns, name=name)
            self.cm_cache[(ns, name)] = (data or {}).get("data", {}) or {}
        return self.cm_cache[(ns, name)]

    def get_secret_text(self, ns, name):
        """Decoded secret data, held in memory only for host extraction. Values are
        NEVER written to any output; see scan_text() secret handling."""
        if (ns, name) not in self.secret_cache:
            data, _ = kget("secret", ns=ns, name=name)
            out = {}
            for k, v in ((data or {}).get("data", {}) or {}).items():
                try:
                    out[k] = base64.b64decode(v).decode("utf-8", "ignore")
                except Exception:
                    out[k] = ""
            self.secret_cache[(ns, name)] = out
        return self.secret_cache[(ns, name)]


# ---------------------------------------------------------------------------
# Edge / result accumulation
# ---------------------------------------------------------------------------

class Capture:
    def __init__(self, cluster):
        self.cluster = cluster
        self.edges = {}         # key -> edge dict
        self.exposed = {}       # (ns,kind,name) -> {"via": set, "publicHosts": set}
        self.public_host_map = {}   # host -> [{"namespace","service","port","internal"}]
        self.unresolved = {}    # host -> {"usedBy": set, "note": str|None}
        self.stages = []        # stage records
        self.notes = []

    def add_edge(self, from_w, to_ns, to_svc, port, protocol, source, evidence, internet_transit=False):
        key = (from_w["namespace"], from_w["kind"], from_w["name"], to_ns, to_svc, port or 0)
        e = self.edges.get(key)
        if e is None:
            e = {
                "from": {"namespace": from_w["namespace"], "kind": from_w["kind"], "name": from_w["name"]},
                "to": {"namespace": to_ns, "service": to_svc,
                       "port": port if port else None, "protocol": protocol or "tcp"},
                "sources": [], "evidence": [], "internetTransit": bool(internet_transit),
            }
            self.edges[key] = e
        if source not in e["sources"]:
            e["sources"].append(source)
        if evidence and evidence not in e["evidence"] and len(e["evidence"]) < 8:
            e["evidence"].append(evidence)
        if internet_transit:
            e["internetTransit"] = True

    def add_exposed(self, w, via, hosts):
        rec = self.exposed.setdefault(self.cluster.workload_key(w), {"via": set(), "publicHosts": set()})
        rec["via"].add(via)
        rec["publicHosts"].update(hosts)

    def add_unresolved(self, host, consumer, note=None):
        if host in IGNORE_HOSTS:
            return
        rec = self.unresolved.setdefault(host, {"usedBy": set(), "note": None})
        rec["usedBy"].add(consumer)
        if note:
            rec["note"] = note

    def record_stage(self, stage, name, resources_found, coverage, verdict, notes=None):
        self.stages.append({
            "stage": stage, "name": name, "resourcesFound": resources_found,
            "coverage": coverage, "verdict": verdict, "notes": notes or [],
        })
        log(f"  stage {stage} ({name}): {verdict}  [{coverage}]")


# ---------------------------------------------------------------------------
# Stage 0 -- entry points
# ---------------------------------------------------------------------------

def _svc_is_internal_lb(meta):
    ann = meta["annotations"]
    checks = (
        ann.get("networking.gke.io/load-balancer-type", "").lower() == "internal",
        ann.get("cloud.google.com/load-balancer-type", "").lower() == "internal",
        ann.get("service.beta.kubernetes.io/aws-load-balancer-internal", "").lower() in ("true", "0.0.0.0/0"),
        ann.get("service.beta.kubernetes.io/aws-load-balancer-scheme", "").lower() == "internal",
        ann.get("service.beta.kubernetes.io/azure-load-balancer-internal", "").lower() == "true",
    )
    return any(checks)


def _ingress_class(ing):
    return ing["spec"].get("ingressClassName") or \
        ing["metadata"].get("annotations", {}).get("kubernetes.io/ingress.class", "") or "(default)"


def _ingress_is_internal(ing):
    cls = _ingress_class(ing).lower()
    return "internal" in cls or "rilb" in cls


def stage0_entry_points(cap):
    cl = cap.cluster
    found = 0
    notes = []

    def register_backend(ns, svc_name, port, host, via, internal, path="/"):
        if host and not internal:
            cap.public_host_map.setdefault(host, [])
            entry = {"namespace": ns, "service": svc_name, "port": port,
                     "internal": internal, "path": path or "/"}
            if entry not in cap.public_host_map[host]:
                cap.public_host_map[host].append(entry)
        if internal:
            return
        for w in cl.workloads_for_service(ns, svc_name):
            cap.add_exposed(w, via, {host} if host else set())

    # Ingresses
    ings, err = kitems("ingresses", all_ns=True)
    if err:
        notes.append(f"ingresses: {err}")
    for ing in ings:
        ns = ing["metadata"]["namespace"]
        if ns not in cl.namespaces:
            continue
        found += 1
        internal = _ingress_is_internal(ing)
        cls = _ingress_class(ing)
        name = ing["metadata"]["name"]
        rules = ing["spec"].get("rules", []) or []
        backends = []  # (host, svc, port, path)
        for rule in rules:
            host = rule.get("host", "") or "*"
            for path in (rule.get("http", {}) or {}).get("paths", []) or []:
                bsvc = (path.get("backend", {}).get("service") or {})
                if bsvc.get("name"):
                    pnum = (bsvc.get("port") or {}).get("number") or (bsvc.get("port") or {}).get("name")
                    backends.append((host, bsvc["name"], pnum, path.get("path") or "/"))
        db = ing["spec"].get("defaultBackend", {}).get("service") or {}
        if db.get("name"):
            pnum = (db.get("port") or {}).get("number") or (db.get("port") or {}).get("name")
            backends.append(("*", db["name"], pnum, "/"))
        for host, svc_name, port, ppath in backends:
            via = f"ingress/{ns}/{name} (class {cls})"
            register_backend(ns, svc_name, port, host if host != "*" else "", via, internal, ppath)

    # Gateway API
    gws, gerr = kitems("gateways.gateway.networking.k8s.io", all_ns=True)
    routes, rerr = kitems("httproutes.gateway.networking.k8s.io", all_ns=True)
    if gerr and "doesn't have a resource type" not in gerr:
        notes.append(f"gateways: {gerr}")
    gw_meta = {}  # (ns, name) -> {"class":, "hostnames": [...], "internal": bool}
    for gw in gws:
        ns, name = gw["metadata"]["namespace"], gw["metadata"]["name"]
        cls = gw["spec"].get("gatewayClassName", "")
        hostnames = [l.get("hostname") for l in gw["spec"].get("listeners", []) if l.get("hostname")]
        internal = "internal" in cls.lower() or "rilb" in cls.lower()
        gw_meta[(ns, name)] = {"class": cls, "hostnames": hostnames, "internal": internal}
        if ns in cl.namespaces:
            found += 1
    for rt in routes:
        ns = rt["metadata"]["namespace"]
        if ns not in cl.namespaces:
            continue
        found += 1
        rname = rt["metadata"]["name"]
        hostnames = rt["spec"].get("hostnames", []) or []
        parents = rt["spec"].get("parentRefs", []) or []
        internal = True
        gw_labels = []
        for p in parents:
            gm = gw_meta.get((p.get("namespace", ns), p.get("name", "")))
            if gm:
                gw_labels.append(f'{p.get("namespace", ns)}/{p.get("name")} (class {gm["class"]})')
                if not gm["internal"]:
                    internal = False
                if not hostnames:
                    hostnames = gm["hostnames"]
        for rule in rt["spec"].get("rules", []) or []:
            match_paths = [(m.get("path", {}) or {}).get("value") or "/"
                           for m in rule.get("matches", []) or []] or ["/"]
            for ref in rule.get("backendRefs", []) or []:
                if ref.get("kind", "Service") != "Service":
                    continue
                b_ns = ref.get("namespace", ns)
                via = f"httproute/{ns}/{rname} -> gateway {', '.join(gw_labels) or '(unresolved parent)'}"
                for host in (hostnames or [""]):
                    for mpath in match_paths:
                        register_backend(b_ns, ref.get("name", ""), ref.get("port"), host, via, internal, mpath)

    # LoadBalancer services
    for (ns, name), meta in sorted(cl.svc_meta.items()):
        if ns not in cl.namespaces or meta["type"] != "LoadBalancer":
            continue
        found += 1
        internal = _svc_is_internal_lb(meta)
        lb_hosts = set()
        for ing in (meta["status"].get("loadBalancer", {}) or {}).get("ingress", []) or []:
            if ing.get("hostname"):
                lb_hosts.add(ing["hostname"])
            if ing.get("ip"):
                lb_hosts.add(ing["ip"])
        via = f"service/{ns}/{name} (LoadBalancer{', internal' if internal else ''})"
        first_port = meta["ports"][0]["port"] if meta["ports"] else None
        for host in (lb_hosts or {""}):
            register_backend(ns, name, first_port, host, via, internal)

    cap.record_stage(0, "entryPoints", found,
                     f"{len(cap.exposed)} internet-exposed workloads; "
                     f"{len(cap.public_host_map)} public hosts mapped",
                     "complete" if found or not err else "absent", notes)


# ---------------------------------------------------------------------------
# Stage 1 -- NetworkPolicy (+ Cilium) permitted-flow graph
# ---------------------------------------------------------------------------

def _policy_edges_for(cap, dest_workloads, src_workloads, ports, source_label, evidence):
    """Emit edges src workload -> service(s) fronting each dest workload."""
    cl = cap.cluster
    for dw in dest_workloads:
        for (sns, sname) in cl.services_selecting(dw):
            port_list = ports or [(p["port"], p["protocol"]) for p in cl.svc_meta[(sns, sname)]["ports"]] or [(None, "tcp")]
            for port, proto in port_list:
                for sw in src_workloads:
                    if cl.workload_key(sw) == cl.workload_key(dw):
                        continue
                    cap.add_edge(sw, sns, sname, port, proto, source_label, evidence)


def stage1_network_policies(cap):
    cl = cap.cluster
    notes = []
    covered = set()
    default_deny_ns = set()
    total_policies = 0
    public_ingress_candidates = []

    pols, err = kitems("networkpolicies", all_ns=True)
    if err:
        notes.append(f"networkpolicies: {err}")
    pols = [p for p in pols if p["metadata"]["namespace"] in cl.namespaces]
    total_policies += len(pols)

    for pol in pols:
        ns, name = pol["metadata"]["namespace"], pol["metadata"]["name"]
        spec = pol.get("spec", {})
        pod_sel = spec.get("podSelector", {})
        ptypes = spec.get("policyTypes") or (["Ingress"] if "ingress" in spec else ["Ingress"])
        selected = cl.workloads_matching(ns, pod_sel)
        for w in selected:
            covered.add(cl.workload_key(w))
        ingress_rules = spec.get("ingress")
        if "Ingress" in ptypes and (pod_sel == {} or not pod_sel) and not ingress_rules:
            default_deny_ns.add(ns)
        for rule in ingress_rules or []:
            ports = [((p.get("port")), (p.get("protocol") or "TCP").lower())
                     for p in rule.get("ports", []) or []]
            src_workloads = []
            for peer in rule.get("from", []) or []:
                ipb = peer.get("ipBlock")
                if ipb:
                    cidr = ipb.get("cidr", "")
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if not net.is_private and net.num_addresses > 1:
                            public_ingress_candidates.append(
                                {"policy": f"{ns}/{name}", "cidr": cidr})
                    except ValueError:
                        pass
                    continue
                ns_sel, pd_sel = peer.get("namespaceSelector"), peer.get("podSelector")
                if ns_sel is not None:
                    peer_namespaces = [n for n, lbl in cl.ns_labels.items() if match_selector(ns_sel, lbl)]
                else:
                    peer_namespaces = [ns]
                for pns in peer_namespaces:
                    if pd_sel is not None:
                        src_workloads += cl.workloads_matching(pns, pd_sel)
                    else:
                        src_workloads += [w for w in cl.workloads if w["namespace"] == pns]
            if src_workloads:
                _policy_edges_for(cap, selected, src_workloads, ports,
                                  "networkPolicy", f"networkPolicy:{ns}/{name}")

    # Cilium policies (evaluated at L3/L4 granularity; L7 sections are ignored)
    cnp, cerr = kitems("ciliumnetworkpolicies", all_ns=True)
    ccnp, ccerr = kitems("ciliumclusterwidenetworkpolicies")
    cilium_found = 0
    if cerr is None or ccerr is None:
        for pol in cnp + ccnp:
            ns = pol["metadata"].get("namespace")  # None for cluster-wide
            if ns and ns not in cl.namespaces:
                continue
            cilium_found += 1
            specs = pol.get("specs") or ([pol["spec"]] if pol.get("spec") else [])
            for spec in specs:
                ep_sel = {"matchLabels": strip_cilium_prefixes(
                    (spec.get("endpointSelector", {}) or {}).get("matchLabels"))}
                scope_ns = [ns] if ns else list(cl.namespaces)
                selected = []
                for sns in scope_ns:
                    selected += cl.workloads_matching(sns, ep_sel)
                for w in selected:
                    covered.add(cl.workload_key(w))
                for rule in spec.get("ingress", []) or []:
                    ports = []
                    for tp in rule.get("toPorts", []) or []:
                        for p in tp.get("ports", []) or []:
                            try:
                                ports.append((int(p.get("port")), (p.get("protocol") or "TCP").lower()))
                            except (TypeError, ValueError):
                                pass
                    src_workloads = []
                    for fe in rule.get("fromEndpoints", []) or []:
                        ml = strip_cilium_prefixes(fe.get("matchLabels"))
                        peer_ns = ml.pop("io.kubernetes.pod.namespace", None)
                        search_ns = [peer_ns] if peer_ns else scope_ns
                        for sns in search_ns:
                            src_workloads += cl.workloads_matching(sns, {"matchLabels": ml})
                    if src_workloads:
                        pname = pol["metadata"]["name"]
                        _policy_edges_for(cap, selected, src_workloads, ports,
                                          "networkPolicy",
                                          f"ciliumNetworkPolicy:{(ns + '/') if ns else 'clusterwide/'}{pname}")
        total_policies += cilium_found
        if cilium_found:
            notes.append(f"{cilium_found} Cilium policies evaluated at L3/L4 (L7 rules ignored)")
    elif cerr and "doesn't have a resource type" not in cerr:
        notes.append(f"ciliumnetworkpolicies: {cerr}")

    total = len(cl.workloads)
    ncov = len(covered)
    dd = len(default_deny_ns & set(cl.namespaces))
    nns = len(cl.namespaces)
    if total_policies == 0:
        verdict = "absent"
    elif ncov == total and dd == nns:
        verdict = "complete"
    else:
        verdict = "partial"
    if public_ingress_candidates:
        notes.append(f"public-CIDR ingress rules found (entry-point candidates, not auto-exposed): "
                     f"{[c['policy'] + ' ' + c['cidr'] for c in public_ingress_candidates]}")
    cap.record_stage(1, "networkPolicies", total_policies,
                     f"{ncov}/{total} workloads selected by >=1 policy; "
                     f"default-deny(ingress) namespaces: {dd}/{nns}",
                     verdict, notes)
    return verdict


# ---------------------------------------------------------------------------
# Stage 2 -- service-mesh authorization / config
# ---------------------------------------------------------------------------

_SPIFFE_RE = re.compile(r"(?:spiffe://)?[^/]*/ns/([^/]+)/sa/(.+)$")


def stage2_mesh(cap):
    cl = cap.cluster
    notes = []
    found = 0
    authz_covered = set()
    default_deny_ns = set()
    sa_index = {}
    for w in cl.workloads:
        sa_index.setdefault((w["namespace"], w["serviceAccount"]), []).append(w)

    # --- Istio ---
    aps, err = kitems("authorizationpolicies.security.istio.io", all_ns=True)
    istio_present = err is None
    if istio_present:
        for ap in aps:
            ns, name = ap["metadata"]["namespace"], ap["metadata"]["name"]
            if ns not in cl.namespaces and ns != "istio-system":
                continue
            found += 1
            spec = ap.get("spec", {}) or {}
            action = spec.get("action", "ALLOW")
            sel = spec.get("selector")
            scope_ns = list(cl.namespaces) if ns == "istio-system" else [ns]
            selected = []
            for sns in scope_ns:
                selected += cl.workloads_matching(sns, sel or {})
            for w in selected:
                authz_covered.add(cl.workload_key(w))
            rules = spec.get("rules")
            if action == "ALLOW" and not rules:
                # allow-nothing = default deny for the selected scope
                for sns in scope_ns:
                    default_deny_ns.add(sns)
                continue
            if action != "ALLOW":
                continue
            for rule in rules or []:
                src_workloads = []
                ports = []
                for to in rule.get("to", []) or []:
                    for p in (to.get("operation", {}) or {}).get("ports", []) or []:
                        try:
                            ports.append((int(p), "tcp"))
                        except (TypeError, ValueError):
                            pass
                for frm in rule.get("from", []) or []:
                    src = frm.get("source", {}) or {}
                    for principal in src.get("principals", []) or []:
                        m = _SPIFFE_RE.match(principal)
                        if m:
                            src_workloads += sa_index.get((m.group(1), m.group(2)), [])
                    for pns in src.get("namespaces", []) or []:
                        src_workloads += [w for w in cl.workloads if w["namespace"] == pns]
                if src_workloads:
                    _policy_edges_for(cap, selected, src_workloads, ports,
                                      "meshAuthorization", f"istioAuthorizationPolicy:{ns}/{name}")

        for res in ("sidecars.networking.istio.io", "virtualservices.networking.istio.io",
                    "destinationrules.networking.istio.io", "serviceentries.networking.istio.io"):
            items, ierr = kitems(res, all_ns=True)
            if ierr is None:
                n = len([i for i in items if i["metadata"].get("namespace") in cl.namespaces])
                found += n
                if n and res.startswith("serviceentries"):
                    hosts = sorted({h for i in items
                                    for h in (i.get("spec", {}).get("hosts") or [])})[:20]
                    notes.append(f"ServiceEntry declared external hosts: {hosts}")

    # --- Linkerd ---
    servers, serr = kitems("servers.policy.linkerd.io", all_ns=True)
    linkerd_present = serr is None
    server_index = {}
    if linkerd_present:
        for srv in servers:
            ns = srv["metadata"]["namespace"]
            if ns not in cl.namespaces:
                continue
            found += 1
            selected = cl.workloads_matching(ns, srv["spec"].get("podSelector") or {})
            port = srv["spec"].get("port")
            server_index[(ns, srv["metadata"]["name"])] = (selected, port)
        sazs, _ = kitems("serverauthorizations.policy.linkerd.io", all_ns=True)
        laps, _ = kitems("authorizationpolicies.policy.linkerd.io", all_ns=True)
        for saz in (sazs or []) + (laps or []):
            ns, name = saz["metadata"]["namespace"], saz["metadata"]["name"]
            if ns not in cl.namespaces:
                continue
            found += 1
            spec = saz.get("spec", {}) or {}
            server_ref = (spec.get("server", {}) or {}).get("name") or \
                         (spec.get("targetRef", {}) or {}).get("name")
            selected, port = server_index.get((ns, server_ref), ([], None))
            for w in selected:
                authz_covered.add(cl.workload_key(w))
            sa_names = []
            mesh_tls = (spec.get("client", {}) or {}).get("meshTLS", {}) or {}
            for sa in mesh_tls.get("serviceAccounts", []) or []:
                sa_names.append((sa.get("namespace", ns), sa.get("name")))
            src_workloads = []
            for key in sa_names:
                src_workloads += sa_index.get(key, [])
            if src_workloads and selected:
                _policy_edges_for(cap, selected, src_workloads,
                                  [(port, "tcp")] if port else [],
                                  "meshAuthorization", f"linkerdServerAuthorization:{ns}/{name}")

    total = len(cl.workloads)
    enrolled = sum(1 for w in cl.workloads if w["mesh_enrolled"])
    ncov = len(authz_covered)
    dd = len(default_deny_ns & set(cl.namespaces))
    if not istio_present and not linkerd_present:
        verdict = "absent"
        notes.append("no Istio or Linkerd policy CRDs found")
    elif found == 0:
        verdict = "absent"
    elif enrolled == total and ncov == total and dd == len(cl.namespaces):
        verdict = "complete"
    else:
        verdict = "partial"
    cap.record_stage(2, "meshAuthorization", found,
                     f"{enrolled}/{total} workloads mesh-enrolled; "
                     f"{ncov}/{total} covered by >=1 authorization policy; "
                     f"default-deny namespaces: {dd}/{len(cl.namespaces)}",
                     verdict, notes)
    return verdict


# ---------------------------------------------------------------------------
# Stage 3 -- observed flows (enrich only)
# ---------------------------------------------------------------------------

def stage3_observed(cap, flows_files, metrics_files):
    cl = cap.cluster
    notes = []
    parsed = added = dropped = 0
    wl_index = {}
    for w in cl.workloads:
        wl_index[(w["namespace"], w["name"])] = w

    def dst_services(dst_ns, dst_workload_name, dst_svc_name):
        if dst_svc_name:
            return [(dst_ns, dst_svc_name)] if (dst_ns, dst_svc_name) in cl.svc_meta else []
        w = wl_index.get((dst_ns, dst_workload_name))
        return cl.services_selecting(w) if w else []

    for path in flows_files:
        try:
            fh = open(path, "r", encoding="utf-8")
        except OSError as e:
            notes.append(f"flows file {path}: {e}")
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                f = obj.get("flow", obj)
                if not isinstance(f, dict) or not f.get("source"):
                    continue
                parsed += 1
                if f.get("is_reply") is True or f.get("verdict") not in (None, "FORWARDED"):
                    dropped += 1
                    continue
                src, dst = f.get("source", {}) or {}, f.get("destination", {}) or {}
                src_ns = src.get("namespace", "")
                src_wls = [(x.get("name"), x.get("kind", "deployment").lower())
                           for x in src.get("workloads", []) or [] if x.get("name")]
                if not src_wls and src.get("pod_name"):
                    # strip replicaset/pod hash suffixes: name-<hash>-<hash> or name-<hash>
                    base = re.sub(r"(-[a-z0-9]{5,10}){1,2}$", "", src["pod_name"])
                    if (src_ns, base) in wl_index:
                        src_wls = [(base, wl_index[(src_ns, base)]["kind"])]
                port = None
                l4 = f.get("l4", {}) or {}
                for proto_key in ("TCP", "UDP"):
                    if proto_key in l4 and l4[proto_key].get("destination_port"):
                        port = l4[proto_key]["destination_port"]
                dsvc = (f.get("destination_service", {}) or {}).get("name") or ""
                dst_ns = (f.get("destination_service", {}) or {}).get("namespace") or dst.get("namespace", "")
                dst_wl = ""
                for x in dst.get("workloads", []) or []:
                    dst_wl = x.get("name", "")
                    break
                when = f.get("time", "")
                for (wname, wkind) in src_wls:
                    w = wl_index.get((src_ns, wname))
                    if not w:
                        continue
                    for (sns, sname) in dst_services(dst_ns, dst_wl, dsvc):
                        proto = DATASTORE_PORTS.get(port, "tcp") if port else "tcp"
                        cap.add_edge(w, sns, sname, port, proto, "observedFlows",
                                     f"flow:hubble {when}".strip())
                        added += 1

    metric_re = re.compile(r"^(istio_requests_total|istio_tcp_sent_bytes_total|request_total|"
                           r"tcp_write_bytes_total)\{([^}]*)\}\s")
    label_re = re.compile(r'(\w+)="([^"]*)"')
    for path in metrics_files:
        try:
            fh = open(path, "r", encoding="utf-8")
        except OSError as e:
            notes.append(f"metrics file {path}: {e}")
            continue
        with fh:
            for line in fh:
                m = metric_re.match(line)
                if not m:
                    continue
                parsed += 1
                labels = dict(label_re.findall(m.group(2)))
                src_ns = labels.get("source_workload_namespace") or labels.get("namespace", "")
                src_wl = labels.get("source_workload") or labels.get("deployment", "")
                dst_ns = labels.get("destination_service_namespace") or labels.get("dst_namespace", "")
                dst_svc = labels.get("destination_service_name") or labels.get("dst_service", "")
                if labels.get("reporter") == "destination":
                    pass  # destination-reported metrics carry the same labels; accept
                w = wl_index.get((src_ns, src_wl))
                if not w or not dst_svc or (dst_ns, dst_svc) not in cl.svc_meta:
                    continue
                cap.add_edge(w, dst_ns, dst_svc, None, "tcp", "observedFlows",
                             f"meshMetrics:{m.group(1)}")
                added += 1

    # Observation can never be "complete": absence of an observed flow proves nothing.
    verdict = "partial" if added else "absent"
    cap.record_stage(3, "observedFlows", parsed,
                     f"{parsed} records parsed, {added} edge enrichments, "
                     f"{dropped} non-forwarded/reply records dropped",
                     verdict, notes)


# ---------------------------------------------------------------------------
# Stage 4 -- declared-config extraction
# ---------------------------------------------------------------------------

def make_resolver(cap):
    """Host resolution against the service index + Stage 0 public-host (hairpin) map."""
    cl = cap.cluster
    sts_pod_re = re.compile(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?)-\d+\.(.+)$", re.I)

    def resolve(host, consumer_ns, url_path=None):
        host = host.strip().rstrip(".")
        if not host or host in IGNORE_HOSTS:
            return None
        # hairpin: public hostname of our own edge -> routed backends, via the internet.
        # When the URL carries a path (never from Secret-sourced text), longest routing
        # path-prefix match narrows the fan-out to the actually-routed backend(s).
        if host in cap.public_host_map:
            entries = [e for e in cap.public_host_map[host] if not e["internal"]]
            if url_path and url_path != "/":
                matched = [e for e in entries
                           if url_path.startswith(e.get("path", "/").rstrip("/") + "/")
                           or url_path == e.get("path", "/").rstrip("/")
                           or e.get("path", "/") == "/"]
                non_root = [e for e in matched if e.get("path", "/") != "/"]
                if non_root:
                    best = max(len(e["path"]) for e in non_root)
                    entries = [e for e in non_root if len(e["path"]) == best]
                elif matched:
                    entries = matched
            targets = sorted({(e["namespace"], e["service"], e["port"]) for e in entries},
                             key=lambda t: (t[0], t[1], str(t[2] or "")))
            if targets:
                return {"kind": "hairpin", "targets": targets, "host": host}
        # exact FQDN / ClusterIP forms
        if host in cl.svc_index and host not in cl.bare_names:
            ns, name = cl.svc_index[host]
            return {"kind": "service", "targets": [(ns, name, None)]}
        # StatefulSet pod DNS: <pod>-N.<svc>[.<ns>.svc...] -> the governing service
        m = sts_pod_re.match(host)
        if m:
            sub = resolve(m.group(3), consumer_ns)
            if sub and sub["kind"] == "service":
                return sub
        # bare service name: same-namespace first, then unique-across-cluster
        if host in cl.bare_names:
            if consumer_ns in cl.bare_names[host]:
                return {"kind": "service", "targets": [(consumer_ns, host, None)]}
            if len(set(cl.bare_names[host])) == 1:
                return {"kind": "service", "targets": [(cl.bare_names[host][0], host, None)]}
        return None

    return resolve


def scan_text(text, consumer_ns, resolve, from_secret=False):
    """Extract (match_kind, scheme, host, port, resolution) tuples from free text.
    Only scheme+host+port ever leave this function -- raw text is never returned,
    which is what makes Secret parsing safe. URL paths are used in memory for
    hairpin routing disambiguation only, and never for Secret-sourced text."""
    hits = []
    seen = set()
    for m in URL_RE.finditer(text):
        scheme, rest = m.group(1).lower(), m.group(2)
        try:
            p = urlparse(f"{scheme}://{rest}")
            host, port, path = p.hostname, p.port, p.path
        except ValueError:
            host, port, path = None, None, None
        if host and (scheme, host, port) not in seen:
            seen.add((scheme, host, port))
            hits.append(("url", scheme, host, port,
                         resolve(host, consumer_ns, None if from_secret else path)))
    for m in HOSTPORT_RE.finditer(text):
        host, port = m.group(1), int(m.group(3))
        if re.fullmatch(r"[\d.]+", host) and host.count(".") != 3:
            continue  # version-string noise like "1.2:80"
        if ("hp", host, port) in seen:
            continue
        seen.add(("hp", host, port))
        res = resolve(host, consumer_ns)
        if res:
            hits.append(("hostport", None, host, port, res))
        elif "." in host and re.search(r"[a-z]", host, re.I) and not re.search(r"\.(so|py|js|json|ya?ml|txt|conf|crt|pem|jar|go|sh)$", host, re.I):
            hits.append(("hostport", None, host, port, None))
    return hits


def _edge_port_proto(scheme, hit_port, target_port, svc_meta):
    port = hit_port or target_port
    if not port and scheme in SCHEME_DEFAULT_PORTS:
        port = SCHEME_DEFAULT_PORTS[scheme]
    if not port and svc_meta and len(svc_meta["ports"]) == 1:
        port = svc_meta["ports"][0]["port"]
    if scheme in ("http", "https", "postgres", "postgresql", "mysql", "redis", "rediss",
                  "mongodb", "amqp", "amqps", "kafka", "ldap", "ldaps", "grpc", "nats"):
        proto = {"postgresql": "postgres", "rediss": "redis", "amqps": "amqp"}.get(scheme, scheme)
    elif port in DATASTORE_PORTS:
        proto = DATASTORE_PORTS[port]
    else:
        proto = "tcp"
    return port, proto


def stage4_declared_config(cap):
    cl = cap.cluster
    resolve = make_resolver(cap)
    notes = []
    workloads_with_edges = set()

    for w in cl.workloads:
        ns = w["namespace"]
        consumer = f'{ns}/{w["kind"]}/{w["name"]}'
        podspec = w["podspec"]
        containers = (podspec.get("containers", []) or []) + (podspec.get("initContainers", []) or [])
        found_any = False
        for c in containers:
            texts = []      # (evidence_label, text, from_secret)
            envmap = {}     # for $(VAR) expansion in command/args and env values
            for e in c.get("env", []) or []:
                name = e.get("name", "")
                if e.get("value"):
                    val = ENV_EXPAND_RE.sub(lambda m: str(envmap.get(m.group(1), m.group(0))), e["value"])
                    envmap[name] = val
                    texts.append((f"env:{name}", val, False))
                vf = e.get("valueFrom", {}) or {}
                if "configMapKeyRef" in vf:
                    r = vf["configMapKeyRef"]
                    val = cl.get_configmap(ns, r["name"]).get(r.get("key", ""), "")
                    envmap[name] = val
                    texts.append((f'env:{name}<-cm/{r["name"]}:{r.get("key", "")}', val, False))
                if "secretKeyRef" in vf:
                    r = vf["secretKeyRef"]
                    val = cl.get_secret_text(ns, r["name"]).get(r.get("key", ""), "")
                    envmap[name] = val
                    texts.append((f'env:{name}<-secret/{r["name"]}:{r.get("key", "")} (value redacted; scheme+host+port only)',
                                  val, True))
            for ef in c.get("envFrom", []) or []:
                if "configMapRef" in ef:
                    for k, v in cl.get_configmap(ns, ef["configMapRef"]["name"]).items():
                        envmap.setdefault(k, v)
                        texts.append((f'envFrom:cm/{ef["configMapRef"]["name"]}:{k}', v, False))
                if "secretRef" in ef:
                    for k, v in cl.get_secret_text(ns, ef["secretRef"]["name"]).items():
                        envmap.setdefault(k, v)
                        texts.append((f'envFrom:secret/{ef["secretRef"]["name"]}:{k} (value redacted; scheme+host+port only)',
                                      v, True))
            argstr = " ".join((c.get("command", []) or []) + (c.get("args", []) or []))
            if argstr:
                argstr = ENV_EXPAND_RE.sub(lambda m: str(envmap.get(m.group(1), m.group(0))), argstr)
                texts.append((f"args:{c.get('name', '')}", argstr, False))

            for label, text, from_secret in texts:
                if not text:
                    continue
                for match_kind, scheme, host, port, res in scan_text(str(text), ns, resolve,
                                                                     from_secret=from_secret):
                    if res:
                        transit = res["kind"] == "hairpin"
                        for (tns, tsvc, tport) in res["targets"]:
                            eport, proto = _edge_port_proto(scheme, port, tport,
                                                            cl.svc_meta.get((tns, tsvc)))
                            ev = label if not transit else f"{label}; hairpin via {res['host']}"
                            cap.add_edge(w, tns, tsvc, eport, proto, "declaredConfig",
                                         ev, internet_transit=transit)
                            found_any = True
                    elif match_kind in ("url", "hostport"):
                        cap.add_unresolved(host, consumer)

        # mounted ConfigMap data
        for v in podspec.get("volumes", []) or []:
            cm_ref = v.get("configMap")
            if not cm_ref:
                continue
            for k, val in cl.get_configmap(ns, cm_ref["name"]).items():
                for match_kind, scheme, host, port, res in scan_text(str(val), ns, resolve):
                    if res:
                        transit = res["kind"] == "hairpin"
                        for (tns, tsvc, tport) in res["targets"]:
                            eport, proto = _edge_port_proto(scheme, port, tport,
                                                            cl.svc_meta.get((tns, tsvc)))
                            ev = f'cm-mount/{cm_ref["name"]}:{k}' + \
                                 (f"; hairpin via {res['host']}" if transit else "")
                            cap.add_edge(w, tns, tsvc, eport, proto, "declaredConfig",
                                         ev, internet_transit=transit)
                            found_any = True
                    elif match_kind == "url":
                        cap.add_unresolved(host, consumer)
        if found_any:
            workloads_with_edges.add(cl.workload_key(w))

    total = len(cl.workloads)
    n = len(workloads_with_edges)
    zero = sorted(f'{k[0]}/{k[1]}/{k[2]}' for k in
                  {cl.workload_key(w) for w in cl.workloads} - workloads_with_edges)
    if zero:
        notes.append(f"workloads with no discovered edge (candidates for image-baked config, "
                     f"needs operator review): {zero}")
    # Declared config can never prove completeness: image-baked configuration is
    # invisible to the API server. "complete" requires operator attestation.
    verdict = "partial" if n else "absent"
    cap.record_stage(4, "declaredConfig", total,
                     f"{n}/{total} workloads with >=1 declared edge; "
                     f"{len(cap.unresolved)} unresolved hosts",
                     verdict, notes)


# ---------------------------------------------------------------------------
# Merge (operator-declared edges + attestation)
# ---------------------------------------------------------------------------

def apply_merge(cap, merge_path, attestation):
    with open(merge_path, "r", encoding="utf-8") as fh:
        doc = parse_simple_yaml(fh.read()) or {}
    if not isinstance(doc, dict):
        raise ValueError(f"--merge file must be a mapping, got {type(doc).__name__}")

    att = doc.get("attestation") or {}
    if "declaredTopologyComplete" in att:
        attestation["declaredTopologyComplete"] = bool(att["declaredTopologyComplete"])
    for k in ("attestedBy", "date", "note"):
        if k in att:
            attestation[k] = str(att[k])  # PyYAML may parse dates as datetime.date

    count = 0
    for e in doc.get("edges") or []:
        frm, to = e.get("from") or {}, e.get("to") or {}
        if not (frm.get("namespace") and frm.get("kind") and frm.get("name") and
                to.get("namespace") and to.get("service")):
            log(f"  ! merge: skipping malformed edge entry: {e}")
            continue
        w = {"namespace": frm["namespace"], "kind": str(frm["kind"]).lower(), "name": frm["name"]}
        for ev in (e.get("evidence") or ["operator-declared edge"]):
            cap.add_edge(w, to["namespace"], to["service"], to.get("port"),
                         to.get("protocol", "tcp"), "operatorDeclared", str(ev),
                         internet_transit=bool(e.get("internetTransit", False)))
        count += 1

    resolved = 0
    for r in doc.get("resolveUnresolved") or []:
        host = r.get("host")
        if not host or host not in cap.unresolved:
            continue
        if r.get("external"):
            cap.unresolved[host]["note"] = r.get("note", "operator-confirmed external destination")
            continue
        to = r.get("to") or {}
        if to.get("namespace") and to.get("service"):
            for consumer in sorted(cap.unresolved[host]["usedBy"]):
                ns, kind, name = consumer.split("/", 2)
                w = {"namespace": ns, "kind": kind, "name": name}
                cap.add_edge(w, to["namespace"], to["service"], to.get("port"),
                             to.get("protocol", "tcp"), "operatorDeclared",
                             f"operator resolved host {host}")
            del cap.unresolved[host]
            resolved += 1

    verdict = "complete" if attestation.get("declaredTopologyComplete") else "partial"
    cap.record_stage(5, "operatorDeclared", count,
                     f"{count} operator edges merged; {resolved} unresolved hosts resolved; "
                     f"declaredTopologyComplete={bool(attestation.get('declaredTopologyComplete'))}",
                     verdict)


# ---------------------------------------------------------------------------
# Output assembly
# ---------------------------------------------------------------------------

def sorted_edges(cap):
    return sorted(cap.edges.values(), key=lambda e: (
        e["from"]["namespace"], e["from"]["kind"], e["from"]["name"],
        e["to"]["namespace"], e["to"]["service"], str(e["to"]["port"] or "")))


def exposed_workloads_list(cap):
    out = []
    for (ns, kind, name), rec in sorted(cap.exposed.items()):
        out.append({
            "namespace": ns, "kind": kind, "name": name,
            "via": sorted(rec["via"]),
            "publicHosts": sorted(h for h in rec["publicHosts"] if h),
        })
    return out


def build_dataflow_doc(cap, attestation, generated):
    sources = []
    order = {"networkPolicies": "networkPolicy", "meshAuthorization": "meshAuthorization",
             "observedFlows": "observedFlows", "declaredConfig": "declaredConfig",
             "operatorDeclared": "operatorDeclared"}
    for st in cap.stages:
        stype = order.get(st["name"])
        if stype and st["verdict"] != "skipped":
            sources.append({"type": stype, "verdict": st["verdict"], "coverage": st["coverage"]})
    edges = []
    for e in sorted_edges(cap):
        item = {
            "from": dict(e["from"]),
            "to": {k: v for k, v in e["to"].items() if v is not None},
            "sources": sorted(e["sources"]),
            "evidence": list(e["evidence"]),
            "internetTransit": e["internetTransit"],
        }
        edges.append(item)
    unresolved = []
    for host in sorted(cap.unresolved):
        rec = {"host": host, "usedBy": sorted(cap.unresolved[host]["usedBy"])}
        if cap.unresolved[host]["note"]:
            rec["note"] = cap.unresolved[host]["note"]
        unresolved.append(rec)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "generated": generated,
        "generator": GENERATOR,
        "sources": sources,
        "attestation": attestation,
        "exposedWorkloads": exposed_workloads_list(cap),
        "edges": edges,
        "unresolved": unresolved,
    }


def write_configmap(doc, out_dir):
    inner = "\n".join(emit_yaml(doc)) + "\n"
    lines = [
        "apiVersion: v1",
        "kind: ConfigMap",
        "metadata:",
        f"  name: {CONFIGMAP_NAME}",
        f"  namespace: {CONFIGMAP_NAMESPACE}",
        "  labels:",
        "    app.kubernetes.io/managed-by: capture-dataflow",
        "    app.kubernetes.io/part-of: trivy-plugin-vdr",
        "data:",
        "  dataflow.yaml: |",
    ]
    lines += ["    " + l if l else "" for l in inner.splitlines()]
    path = os.path.join(out_dir, "configmap.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def write_bundle(cap, doc, args, generated, out_dir):
    bundle = {
        "generated": generated,
        "generator": GENERATOR,
        "kubectlContext": current_context(),
        "arguments": [a for a in sys.argv[1:]],
        "namespaces": sorted(cap.cluster.namespaces),
        "stages": cap.stages,
        "publicHostMap": {h: v for h, v in sorted(cap.public_host_map.items())},
        "workloads": [
            {"namespace": w["namespace"], "kind": w["kind"], "name": w["name"],
             "serviceAccount": w["serviceAccount"], "meshEnrolled": w["mesh_enrolled"],
             "exposed": cap.cluster.workload_key(w) in cap.exposed,
             "hasEdges": any(e["from"] == {"namespace": w["namespace"], "kind": w["kind"],
                                           "name": w["name"]} for e in cap.edges.values())}
            for w in sorted(cap.cluster.workloads,
                            key=lambda x: (x["namespace"], x["kind"], x["name"]))
        ],
        "dataflow": doc,
    }
    path = os.path.join(out_dir, "bundle.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, sort_keys=False, default=str)
        fh.write("\n")
    return path


# ---------------------------------------------------------------------------
# Mermaid
# ---------------------------------------------------------------------------

def _mermaid_id(prefix, label, registry):
    import hashlib
    sanitized = re.sub(r"[^A-Za-z0-9]", "_", label)
    if len(sanitized) > 48:
        digest = hashlib.md5(sanitized.encode()).hexdigest()[:6]
        sanitized = sanitized[:40].rstrip("_") + "_" + digest
    base = prefix + sanitized
    node_id = base
    i = 2
    while node_id in registry and registry[node_id] != label:
        node_id = f"{base}_{i}"
        i += 1
    registry[node_id] = label
    return node_id


def write_mermaid(cap, doc, generated, out_dir):
    diagrams_dir = os.path.join(out_dir, "diagrams")
    os.makedirs(diagrams_dir, exist_ok=True)
    exposed_ns = sorted({e["namespace"] for e in doc["exposedWorkloads"]})
    exposed_keys = {(e["namespace"], e["kind"], e["name"]) for e in doc["exposedWorkloads"]}
    written = []

    for ns in exposed_ns:
        lines = [
            f"%% vdr-dataflow: namespace {ns}",
            f"%% generated: {generated} by {GENERATOR}",
            f"%% sources: {', '.join(s['type'] + '=' + s['verdict'] for s in doc['sources']) or 'none'}",
            "%% legend: red=internet-exposed workload, blue=internal, green cylinder=datastore,",
            "%%         solid=declared/policy/observed edge, orange dashed=hairpin via internet (internetTransit),",
            "%%         gray dotted=unresolved/external host, dashed box=foreign namespace",
            "flowchart LR",
            '  internet(("Internet")):::internet',
        ]
        registry = {}
        node_defs = []          # (node_id, definition_line, container_ns_or_None)
        defined = set()
        links = []              # (line, style) style in None|"hairpin"|"unresolved"
        cls = {"exposed": set(), "internal": set(), "datastore": set(), "edgez": set()}

        ns_edges = [e for e in doc["edges"]
                    if e["from"]["namespace"] == ns or e["to"]["namespace"] == ns]
        ns_exposed = [e for e in doc["exposedWorkloads"] if e["namespace"] == ns]

        def workload_node(wns, wkind, wname):
            label = f"{wkind}/{wname}"
            nid = _mermaid_id("w_", f"{wns}_{label}", registry)
            if nid not in defined:
                defined.add(nid)
                node_defs.append((nid, f'{nid}["{label}"]', None if wns == ns else wns))
                cls["exposed" if (wns, wkind, wname) in exposed_keys else "internal"].add(nid)
            return nid

        def service_node(sns, sname, port):
            nid = _mermaid_id("s_", f"{sns}_{sname}", registry)
            if nid not in defined:
                defined.add(nid)
                if port in DATASTORE_PORTS:
                    label = f"{sname}<br/>({DATASTORE_PORTS[port]}:{port})"
                    node_defs.append((nid, f'{nid}[("{label}")]', None if sns == ns else sns))
                    cls["datastore"].add(nid)
                else:
                    node_defs.append((nid, f'{nid}["svc {sname}"]', None if sns == ns else sns))
                    cls["internal"].add(nid)
            elif port in DATASTORE_PORTS and nid not in cls["datastore"]:
                pass  # first definition wins; port variance noted via edge labels
            return nid

        # Edge zone: internet -> ingress/gateway/LB -> exposed workload
        edge_zone_nodes = []
        for ew in ns_exposed:
            wnid = workload_node(ew["namespace"], ew["kind"], ew["name"])
            for via in ew["via"]:
                hosts = ", ".join(ew["publicHosts"][:2]) or ""
                label = via + (f"<br/>{hosts}" if hosts else "")
                enid = _mermaid_id("e_", via, registry)
                if enid not in defined:
                    defined.add(enid)
                    edge_zone_nodes.append(f'    {enid}["{label}"]')
                    cls["edgez"].add(enid)
                    links.append((f"  internet --> {enid}", None))
                links.append((f"  {enid} --> {wnid}", None))

        if edge_zone_nodes:
            lines.append(f'  subgraph edgezone["Edge: ingress / gateway / LB"]')
            lines += sorted(set(edge_zone_nodes))
            lines.append("  end")

        # Dataflow edges
        for e in ns_edges:
            f, t = e["from"], e["to"]
            wnid = workload_node(f["namespace"], f["kind"], f["name"])
            snid = service_node(t["namespace"], t["service"], t.get("port"))
            plabel = str(t.get("port") or "")
            if t.get("protocol") and t["protocol"] != "tcp":
                plabel = f'{t["protocol"]}{":" + plabel if plabel else ""}'
            if e["internetTransit"]:
                lbl = f"hairpin{' ' + plabel if plabel else ''}"
                links.append((f"  {wnid} -->|{lbl}| {snid}", "hairpin"))
            elif plabel:
                links.append((f"  {wnid} -->|{plabel}| {snid}", None))
            else:
                links.append((f"  {wnid} --> {snid}", None))

        # Unresolved / external hosts used by workloads in this namespace
        for u in doc["unresolved"]:
            consumers = [c for c in u["usedBy"] if c.startswith(ns + "/")]
            if not consumers:
                continue
            unid = _mermaid_id("x_", u["host"], registry)
            if unid not in defined:
                defined.add(unid)
                note = u.get("note")
                label = f'ext: {u["host"]}' + (f"<br/>{note}" if note else "")
                node_defs.append((unid, f'{unid}["{label}"]', None))
                cls["internal"].add(unid)  # styled by link, kept neutral fill
            for c in consumers:
                cns, ckind, cname = c.split("/", 2)
                wnid = workload_node(cns, ckind, cname)
                links.append((f"  {wnid} --> {unid}", "unresolved"))

        # Node definitions: local first, foreign namespaces in dashed subgraphs
        foreign = {}
        for nid, definition, container in node_defs:
            if container is None:
                lines.append("  " + definition)
            else:
                foreign.setdefault(container, []).append(definition)
        for fns in sorted(foreign):
            sub_id = "ns_" + re.sub(r"[^A-Za-z0-9]", "_", fns)
            lines.append(f'  subgraph {sub_id}["namespace: {fns}"]')
            lines += ["    " + d for d in foreign[fns]]
            lines.append("  end")
            lines.append(f"  style {sub_id} stroke-dasharray: 5 5,stroke:#666")

        link_lines, hairpin_idx, unresolved_idx = [], [], []
        for i, (line, style) in enumerate(links):
            link_lines.append(line)
            if style == "hairpin":
                hairpin_idx.append(i)
            elif style == "unresolved":
                unresolved_idx.append(i)
        lines += link_lines

        lines += [
            "  classDef internet fill:#f5f5f5,stroke:#333,color:#111",
            "  classDef edgez fill:#fdf2e9,stroke:#d35400,color:#111",
            "  classDef exposed fill:#fadbd8,stroke:#c0392b,stroke-width:2px,color:#111",
            "  classDef internal fill:#d6eaf8,stroke:#2e6da4,color:#111",
            "  classDef datastore fill:#d5f5e3,stroke:#1e8449,color:#111",
        ]
        for cname in ("edgez", "exposed", "internal", "datastore"):
            if cls[cname]:
                lines.append(f"  class {','.join(sorted(cls[cname]))} {cname}")
        if hairpin_idx:
            lines.append(f"  linkStyle {','.join(map(str, hairpin_idx))} "
                         f"stroke:#d35400,stroke-width:2px,stroke-dasharray:6 4")
        if unresolved_idx:
            lines.append(f"  linkStyle {','.join(map(str, unresolved_idx))} "
                         f"stroke:#888,stroke-dasharray:2 3")

        path = os.path.join(diagrams_dir, f"{ns}.mmd")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        written.append(path)
    return written


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="capture_dataflow.py",
        description="Staged, read-only Kubernetes dataflow capture for trivy-plugin-vdr. "
                    "Uses kubectl get/list ONLY; never exec, never apply.")
    scope = p.add_mutually_exclusive_group(required=True)
    scope.add_argument("--namespaces", action="append", default=None,
                       help="comma-separated namespaces to analyze (repeatable)")
    scope.add_argument("--all-namespaces", action="store_true",
                       help=f"analyze all namespaces except system prefixes {SYSTEM_NS_PREFIXES}")
    p.add_argument("--exclude-namespaces", default="",
                   help="comma-separated namespaces to exclude (in addition to system defaults)")
    p.add_argument("--flows-file", action="append", default=[],
                   help="Hubble/Cilium flow JSON export (jsonl); enrich-only, repeatable")
    p.add_argument("--mesh-metrics-file", action="append", default=[],
                   help="Istio/Linkerd Prometheus metrics snapshot; enrich-only, repeatable")
    p.add_argument("--all-stages", action="store_true",
                   help="run every stage even after a stage reports a complete map")
    p.add_argument("--merge", default=None, metavar="OPERATOR_EDGES_YAML",
                   help="merge operator-declared edges + attestation (source: operatorDeclared)")
    p.add_argument("--output-dir", default="./vdr-dataflow-output")
    p.add_argument("--emit", choices=("bundle", "configmap", "mermaid", "all"), default="all")
    return p.parse_args(argv)


def select_namespaces(args):
    excludes = {n.strip() for n in args.exclude_namespaces.split(",") if n.strip()}
    if args.all_namespaces:
        items, err = kitems("namespaces")
        if err:
            log(f"fatal: cannot list namespaces: {err}")
            sys.exit(2)
        names = [n["metadata"]["name"] for n in items]
        return sorted(n for n in names
                      if not n.startswith(SYSTEM_NS_PREFIXES) and n not in excludes)
    out = []
    for group in args.namespaces:
        out += [n.strip() for n in group.split(",") if n.strip()]
    return sorted(set(out) - excludes)


def main(argv=None):
    args = parse_args(argv)
    namespaces = select_namespaces(args)
    if not namespaces:
        log("fatal: no namespaces selected")
        return 2
    generated = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log(f"capture-dataflow {VERSION} | context: {current_context()}")
    log(f"namespaces: {', '.join(namespaces)}")
    log("read-only guarantee: kubectl get/list only; nothing is applied to the cluster")

    cluster = Cluster(namespaces)
    cluster.load()
    log(f"inventory: {len(cluster.workloads)} workloads, "
        f"{len(cluster.services)} services in scope")
    cap = Capture(cluster)

    # Stage 0 always runs: exposure + hairpin map are needed regardless of graph source.
    stage0_entry_points(cap)

    v1 = stage1_network_policies(cap)
    have_complete = (v1 == "complete")

    if args.all_stages or not have_complete:
        v2 = stage2_mesh(cap)
        have_complete = have_complete or (v2 == "complete")
    else:
        cap.record_stage(2, "meshAuthorization", 0,
                         "skipped: stage 1 yielded a complete permitted-flow map", "skipped")

    # Stage 3 runs whenever its inputs are supplied: observed flows only ever enrich.
    if args.flows_file or args.mesh_metrics_file:
        stage3_observed(cap, args.flows_file, args.mesh_metrics_file)

    if args.all_stages or not have_complete:
        stage4_declared_config(cap)
    else:
        cap.record_stage(4, "declaredConfig", 0,
                         "skipped: an enforcement stage yielded a complete permitted-flow map",
                         "skipped")

    attestation = {
        "declaredTopologyComplete": False,
        "attestedBy": "",
        "date": "",
        "note": "no operator attestation provided",
    }
    if args.merge:
        apply_merge(cap, args.merge, attestation)

    doc = build_dataflow_doc(cap, attestation, generated)

    out_dir = args.output_dir
    os.makedirs(out_dir, exist_ok=True)
    written = []
    if args.emit in ("bundle", "all"):
        written.append(write_bundle(cap, doc, args, generated, out_dir))
    if args.emit in ("configmap", "all"):
        written.append(write_configmap(doc, out_dir))
    if args.emit in ("mermaid", "all"):
        written += write_mermaid(cap, doc, generated, out_dir)

    log(f"\nedges: {len(doc['edges'])} | exposed workloads: {len(doc['exposedWorkloads'])} | "
        f"unresolved hosts: {len(doc['unresolved'])}")
    for w in written:
        log(f"wrote {w}")
    if args.emit in ("configmap", "all"):
        log("\nNOT applied to the cluster. Review, then apply manually or via GitOps:")
        log(f"  kubectl apply -f {os.path.join(out_dir, 'configmap.yaml')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
