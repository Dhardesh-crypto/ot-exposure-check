"""Client deliverables: report, findings register and retest comparison."""

import csv
import io
import json
import re
from importlib import resources
from pathlib import Path

import yaml
from jinja2 import Environment, select_autoescape

from . import checklist, evidence, exposure, inventory, portfolio, report
from .engagement import site_folder, today
from .site import SiteError

COLUMNS = ("ID", "Site", "Severity", "Category", "Finding", "Evidence", "What to do", "Owner", "Due date")


def safe_cell(value):
    """Stop spreadsheet software treating untrusted text as a formula."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def _evidence_label(item, records):
    if item["source"] == "scan":
        return "Scan data, last seen %s (%s)" % (item["seen"], item["confidence"])
    if item["source"] == "traffic":
        return "Supplied network logs"
    if item["source"] == "asset":
        return "Supplied asset list"
    entry = records.get(item["key"].split(":", 1)[1])
    if not entry:
        return "Answer with no source recorded"
    return "%s, from %s%s" % (entry["status"].capitalize(), entry["source"],
                              ": " + entry["evidence"] if entry["evidence"] else "")


def site_model(engagement, folder, slug):
    path = site_folder(folder, slug)
    site = engagement.as_site(slug)
    questions = checklist.load_questions(site.sector)
    traffic = inventory.load("inventory.json", path)
    extra = (traffic or {}).get("findings", []) + inventory.load("matches.json", path, [])
    model = report.build(site, exposure.load(path), questions, checklist.load_answers(path), extra)
    records = evidence.load(path)
    model["slug"] = slug
    model["traffic"] = traffic
    model["assets"] = inventory.load("assets.json", path, [])
    model["good_answers_stated"] = sum(
        1 for key, entry in records.items()
        if entry["status"] == "stated" and entry["answer"] in ("yes", "na")
    )
    for item in model["findings"]:
        item["id"] = "%s|%s" % (slug, item["key"])
        item["site"] = site.name
        item["evidence_label"] = _evidence_label(item, records)
    return model


def build(engagement, folder):
    if not engagement.sites:
        raise SiteError("Add a site first.")
    models = {slug: site_model(engagement, folder, slug) for slug in engagement.sites}
    findings = sorted((item for model in models.values() for item in model["findings"]), key=report.rank)
    contractors = {slug: record["contractor"] for slug, record in engagement.sites.items()}
    used = sorted({ref for item in findings for ref in item["refs"]})
    text = resources.files("otcheck").joinpath("rules/references.yaml").read_text("utf-8")
    references = yaml.safe_load(text)
    retest = inventory.load("retest.json", folder)
    return {
        "engagement": engagement,
        "issued": today().isoformat(),
        "models": list(models.values()),
        "findings": findings,
        "patterns": portfolio.analyse(models, contractors),
        "counts": {level: sum(1 for item in findings if item["severity"] == level) for level in report.SEVERITY_ORDER},
        "complete": all(model["complete"] for model in models.values()),
        "references": [dict(references[ref], id=ref) for ref in used],
        "retest": retest,
    }


def register_csv(findings):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(COLUMNS)
    for item in findings:
        writer.writerow([safe_cell(value) for value in (
            item["id"], item["site"], item["severity"], item["category_label"], item["title"],
            item["evidence_label"], item["fix"], "", "",
        )])
    return buffer.getvalue()


def _css():
    template = resources.files("otcheck").joinpath("templates/report.html").read_text("utf-8")
    return re.search(r"<style>(.*?)</style>", template, re.S).group(1)


def render(model):
    environment = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    text = resources.files("otcheck").joinpath("templates/client_report.html").read_text("utf-8")
    return environment.from_string(text).render(css=_css(), **model)


def snapshot(findings):
    return {item["id"]: {"title": item["title"], "site": item["site"], "severity": item["severity"]}
            for item in findings}


def write(model, folder):
    out = Path(folder) / "deliverables"
    out.mkdir(exist_ok=True)
    (out / "client-report.html").write_text(render(model), encoding="utf-8")
    (out / "findings.csv").write_text(register_csv(model["findings"]), encoding="utf-8")
    (out / "findings.json").write_text(json.dumps(snapshot(model["findings"]), indent=2) + "\n", encoding="utf-8")
    return out


def compare(baseline_path, findings):
    try:
        baseline = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SiteError("Could not read the baseline findings.json.") from None
    current = snapshot(findings)
    pick = lambda source, keys: [dict(source[key], id=key) for key in sorted(keys)]
    return {
        "baseline": Path(baseline_path).name,
        "compared_on": today().isoformat(),
        "not_found": pick(baseline, set(baseline) - set(current)),
        "still_open": pick(current, set(baseline) & set(current)),
        "new": pick(current, set(current) - set(baseline)),
    }
