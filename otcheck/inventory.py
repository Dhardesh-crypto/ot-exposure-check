"""Passive asset inventory from network logs the client supplies as files.

This reads Zeek or Malcolm output. It doesn't capture traffic and it opens no
connections. Only a summary is kept, never the raw logs.
"""

import csv
import ipaddress
import json
from collections import Counter
from pathlib import Path

from . import exposure
from .site import SiteError, is_documentation

REFS = ["cisa-2025", "cisa-aa25-343a"]
FRAMEWORKS = ["CISA CPG 2.F", "IEC 62443 FR5", "NIS2 Art. 21(2)(i)"]
ASSET_FIELDS = ("ip", "make", "model", "firmware")


def _pick(row, *names):
    """Read a field written flat ("source.ip") or nested ({"source": {"ip": ...}})."""
    for name in names:
        if name in row:
            return row[name]
        value = row
        for part in name.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value is not None:
            return value
    return None


def _flow(row):
    source = _pick(row, "id.orig_h", "source.ip")
    target = _pick(row, "id.resp_h", "destination.ip")
    port = _pick(row, "id.resp_p", "destination.port")
    service = _pick(row, "service", "network.protocol")
    try:
        source, target = ipaddress.ip_address(source), ipaddress.ip_address(target)
        port = int(port)
    except (TypeError, ValueError):
        return None
    if isinstance(service, list):
        service = service[0] if service else ""
    return {"source": str(source), "target": str(target), "port": port,
            "service": str(service or "").lower()[:40]}


def _zeek_rows(lines):
    fields = None
    for line in lines:
        if line.startswith("#fields"):
            fields = line.rstrip("\n").split("\t")[1:]
        elif line.startswith("#") or not line.strip():
            continue
        elif fields:
            yield dict(zip(fields, line.rstrip("\n").split("\t")))


def parse_log(text):
    """Return (flows, rows skipped). Accepts Zeek TSV, and Zeek or Malcolm JSON lines."""
    lines = text.splitlines()
    if any(line.startswith("#fields") for line in lines[:20]):
        rows = list(_zeek_rows(lines))
    else:
        rows = []
        for line in lines:
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    rows.append({})
    flows = [_flow(row) if isinstance(row, dict) else None for row in rows]
    good = [flow for flow in flows if flow]
    return good, len(flows) - len(good)


def _is_public(address):
    ip = ipaddress.ip_address(address)
    return ip.is_global or is_documentation(address)


def _protocols():
    """Industrial and remote screen services, taken from the exposure rules."""
    by_port, by_service = {}, {}
    for rule in exposure.load_rules()["rules"]:
        if rule["severity"] == "critical":
            for port in rule["ports"]:
                by_port[port] = rule["name"]
            for module in rule["modules"]:
                by_service[module] = rule["name"]
    return by_port, by_service


def _finding(key, severity, title, why, fix, action):
    return {"key": key, "title": title, "category": "exposure", "severity": severity,
            "why": why, "fix": fix, "action": action, "refs": REFS,
            "frameworks": FRAMEWORKS, "source": "traffic"}


def analyse(flows, control_networks=(), skipped=0):
    by_port, by_service = _protocols()
    networks = [ipaddress.ip_network(value) for value in control_networks]

    def in_control(address):
        ip = ipaddress.ip_address(address)
        return any(ip.version == net.version and ip in net for net in networks)

    devices, talkers, findings = {}, Counter(), {}
    for flow in flows:
        protocol = by_service.get(flow["service"]) or by_port.get(flow["port"])
        source, target = flow["source"], flow["target"]
        if protocol:
            device = devices.setdefault(target, {"ip": target, "protocols": set(), "clients": set()})
            device["protocols"].add(protocol)
            device["clients"].add(source)
            talkers[(source, target, protocol)] += 1
            if _is_public(source) and not _is_public(target):
                findings["traffic:inbound:%s:%s" % (target, flow["port"])] = (
                    "critical", "%s traffic reached %s from the internet address %s" % (protocol, target, source),
                    "Control traffic is arriving from outside the site, so this device may be reachable from the internet.",
                    "Agree a plan with the operator, then block this path and find out who the outside address belongs to.",
                    "Investigate and block %s traffic from %s to %s." % (protocol, source, target))
            elif networks and in_control(target) and not in_control(source) and not _is_public(source):
                findings["traffic:crossing:%s:%s:%s" % (source, target, flow["port"])] = (
                    "high", "%s traffic from %s, outside the control network, reached %s" % (protocol, source, target),
                    "A device outside the control network can talk to a controller, so a problem there could spread.",
                    "Confirm whether this path is needed. Route it through a firewall or demilitarised zone, or remove it.",
                    "Review the path from %s to %s." % (source, target))

    for flow in flows:
        if flow["source"] in devices and _is_public(flow["target"]):
            findings["traffic:outbound:%s" % flow["source"]] = (
                "high", "Control device %s connected to the internet address %s" % (flow["source"], flow["target"]),
                "Control devices rarely need to reach the internet, and this could be a vendor link or something worse.",
                "Find out what this connection is and who owns it. Block it unless there's a documented reason.",
                "Identify the outbound connection from %s." % flow["source"])

    return {
        "flows_read": len(flows),
        "rows_skipped": skipped,
        "devices": [
            {"ip": item["ip"], "protocols": sorted(item["protocols"]), "clients": sorted(item["clients"])}
            for item in sorted(devices.values(), key=lambda entry: entry["ip"])
        ],
        "findings": [_finding(key, *values) for key, values in sorted(findings.items())],
    }


def import_logs(paths, control_networks):
    flows, skipped = [], 0
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            raise SiteError("Could not read %s." % path) from None
        found, missed = parse_log(text)
        flows.extend(found)
        skipped += missed
    if not flows:
        raise SiteError("No connection records found. Supply a Zeek conn.log or Malcolm export.")
    return analyse(flows, control_networks, skipped)


def import_assets(path):
    """Read a walk-down asset list: CSV with ip, make, model and firmware columns."""
    try:
        with open(path, newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            missing = set(ASSET_FIELDS) - set(reader.fieldnames or ())
            if missing:
                raise SiteError("The asset file needs these columns: %s." % ", ".join(sorted(missing)))
            return [{key: (row.get(key) or "").strip()[:80] for key in ASSET_FIELDS} for row in reader]
    except OSError:
        raise SiteError("Could not read %s." % path) from None


def save(data, name, folder):
    Path(folder, name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load(name, folder, default=None):
    path = Path(folder) / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default
