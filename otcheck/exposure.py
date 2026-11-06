"""Find exposed control systems in third-party internet scan data.

This module reads what a scanning service has already recorded. It does not
connect to the site's addresses; see net.py.
"""

import json
import re
import time
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path

import yaml

from . import net
from .site import SiteError, is_documentation

STALE_AFTER_DAYS = 30


def load_rules():
    text = resources.files("otcheck").joinpath("rules/exposure.yaml").read_text("utf-8")
    return yaml.safe_load(text)


def parse_export(text):
    """Read a Shodan host result, a list of banners, or newline-delimited banners."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = [json.loads(line) for line in text.splitlines() if line.strip()]
        except ValueError:
            raise SiteError("That file is not a Shodan JSON export.") from None
    if isinstance(data, dict):
        address = data.get("ip_str")
        banners = data.get("data", [data])
        return [dict(b, ip_str=b.get("ip_str", address)) for b in banners]
    if isinstance(data, list):
        return [b for b in data if isinstance(b, dict)]
    raise SiteError("That file is not a Shodan JSON export.")


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _service(banner):
    """Keep only short identifying fields. Raw banners can hold sensitive detail."""
    http = banner.get("http") if isinstance(banner.get("http"), dict) else {}
    meta = banner.get("_shodan") if isinstance(banner.get("_shodan"), dict) else {}
    return {
        "ip": _text(banner.get("ip_str")),
        "port": banner.get("port"),
        "transport": _text(banner.get("transport")) or "tcp",
        "module": _text(meta.get("module")).lower(),
        "product": _text(banner.get("product"))[:80],
        "version": _text(banner.get("version"))[:40],
        "title": _text(http.get("title"))[:80],
        "seen": _text(banner.get("timestamp"))[:10],
    }


def _has_word(word, text):
    # Whole words only, so "hmi" does not match a page titled "Schmidt".
    return re.search(r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(word), text) is not None


def match(service, rules):
    """Return (rule, confidence), preferring protocol evidence over a port number."""
    haystack = ("%s %s" % (service["product"], service["title"])).lower()
    for rule in rules:
        if service["module"] in rule["modules"]:
            return rule, "confirmed"
        if any(_has_word(word, haystack) for word in rule["keywords"]):
            return rule, "confirmed"
    for rule in rules:
        if service["port"] in rule["ports"]:
            return rule, "port only"
    return None, None


def _is_stale(seen, now):
    try:
        date = datetime.strptime(seen, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return now - date > timedelta(days=STALE_AFTER_DAYS)


def analyse(banners, addresses, source, now=None):
    """Turn scan banners into a result, ignoring anything outside the site."""
    now = now or datetime.now(timezone.utc)
    config = load_rules()
    allowed = set(addresses)
    findings, other, seen_ips, skipped, keys = [], [], set(), 0, set()
    for banner in banners:
        service = _service(banner)
        if service["ip"] not in allowed:
            skipped += 1
            continue
        seen_ips.add(service["ip"])
        key = (service["ip"], service["port"], service["transport"])
        if key in keys:
            continue
        keys.add(key)
        rule, confidence = match(service, config["rules"])
        if rule is None:
            other.append(service)
            continue
        severity = rule["severity"]
        if confidence == "port only" and severity == "critical":
            severity = "high"
        findings.append(
            {
                "rule": rule["id"],
                "name": rule["name"],
                "severity": severity,
                "confidence": confidence,
                "why": rule["why"],
                "service": service,
                "stale": _is_stale(service["seen"], now),
            }
        )
    return {
        "source": source,
        "checked_on": now.date().isoformat(),
        "addresses_checked": sorted(allowed),
        "addresses_without_data": sorted(allowed - seen_ips),
        "out_of_scope_skipped": skipped,
        "findings": findings,
        "other_services": other,
    }


def import_file(path, addresses):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        raise SiteError("Could not read %s." % path) from None
    return analyse(parse_export(text), addresses, "Imported file: %s" % Path(path).name)


def live_lookup(addresses, api_key, pause=1.0):
    """Ask Shodan what it has recorded about each site address."""
    if not api_key:
        raise SiteError(
            "Set the SHODAN_API_KEY environment variable, or use --import with an "
            "export file."
        )
    banners = []
    for index, address in enumerate(addresses):
        if is_documentation(address):
            raise SiteError("%s is a simulated address. Use --import." % address)
        if index and pause:
            time.sleep(pause)  # Stay within Shodan's published request rate.
        host = net.get_json(
            "https://api.shodan.io/shodan/host/%s?key=%s" % (address, api_key)
        )
        if host:
            banners.extend(parse_export(json.dumps(host)))
    return analyse(banners, addresses, "Shodan live lookup")


def save(result, folder):
    path = Path(folder) / "exposure.json"
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def load(folder):
    path = Path(folder) / "exposure.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
