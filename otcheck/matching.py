"""Compare an asset list with support status and known-exploited lists.

A match is a prompt to check, never proof that a device is vulnerable.
"""

import re
from importlib import resources

import yaml

from . import net
from .site import SiteError

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FRAMEWORKS = ["CISA CPG 1.A", "NIS2 Art. 21(2)(e)"]


def load_rules():
    text = resources.files("otcheck").joinpath("rules/lifecycle.yaml").read_text("utf-8")
    return yaml.safe_load(text)["products"]


def fetch_kev():
    data = net.get_json(KEV_URL)
    if not data or "vulnerabilities" not in data:
        raise SiteError("CISA's list came back in an unexpected format.")
    return data


def _version(text):
    numbers = re.findall(r"\d+", text or "")
    return tuple(int(number) for number in numbers) or None


def _is_older(firmware, fixed):
    """True, False, or None when the firmware can't be read."""
    current, target = _version(firmware), _version(fixed)
    if current is None:
        return None
    size = max(len(current), len(target))
    return current + (0,) * (size - len(current)) < target + (0,) * (size - len(target))


def _same_model(rule_model, model):
    pattern = r"(?<![a-z0-9])%s(?![a-z0-9])" % re.escape(rule_model)
    return re.search(pattern, model.lower()) is not None


def _finding(key, severity, title, why, fix, refs):
    return {"key": key, "title": title, "category": "resilience", "severity": severity,
            "why": why, "fix": fix, "action": fix, "refs": refs,
            "frameworks": FRAMEWORKS, "source": "asset"}


def _lifecycle(asset, rule):
    name = "%s %s" % (asset["make"], asset["model"])
    where = asset["ip"] or "address not recorded"
    key = "asset:%s:%s" % (rule["model"].replace(" ", "-"), where)
    if rule.get("status") == "end of life":
        return _finding(key, "high", "Check: %s at %s appears to be end of life" % (name, where),
                        rule["detail"], "Confirm the model with the vendor and plan its replacement.", rule["refs"])
    older = _is_older(asset["firmware"], rule["fixed_in"])
    if older is False:
        return None
    state = "firmware %s" % asset["firmware"] if older else "unknown firmware"
    return _finding(key, "high", "Check: %s at %s has %s" % (name, where, state),
                    "%s (%s)" % (rule["detail"], ", ".join(rule["cves"])),
                    "Confirm the firmware, then update it to %s or later with the vendor." % rule["fixed_in"],
                    rule["refs"])


def match(assets, kev=None):
    findings = []
    for asset in assets:
        make = asset["make"].lower()
        for rule in load_rules():
            if rule["make"] in make and _same_model(rule["model"], asset["model"]):
                result = _lifecycle(asset, rule)
                if result:
                    findings.append(result)
        for entry in (kev or {}).get("vulnerabilities", []):
            vendor = str(entry.get("vendorProject", "")).lower()
            product = str(entry.get("product", "")).lower()
            if vendor and product and vendor in make and product in asset["model"].lower():
                cve = str(entry.get("cveID", "unknown"))[:30]
                findings.append(_finding(
                    "kev:%s:%s" % (cve, asset["ip"]), "medium",
                    "Check: %s lists %s for this product family (%s %s)" % ("CISA", cve, asset["make"], asset["model"]),
                    "This flaw is known to be exploited, but a name match doesn't show this device is affected.",
                    "Check the vendor advisory against the installed version.", ["cisa-kev"]))
    return findings
