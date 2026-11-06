"""Turn results into a prioritised, self-contained HTML report."""

from importlib import resources
from pathlib import Path

import yaml
from jinja2 import Environment, select_autoescape

from . import checklist, exposure

CATEGORY_ORDER = {"exposure": 0, "access": 1, "resilience": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}
CATEGORY_LABELS = {
    "exposure": "Internet exposure",
    "access": "Access",
    "resilience": "Resilience",
}


def _exposure_findings(result, config):
    items = []
    for finding in result["findings"] if result else []:
        service = finding["service"]
        evidence = ", ".join(
            part for part in (service["product"], service["version"], service["title"]) if part
        )
        items.append(
            {
                "title": "%s visible on %s port %s"
                % (finding["name"], service["ip"], service["port"]),
                "category": "exposure",
                "severity": finding["severity"],
                "why": finding["why"],
                "fix": config["fix"],
                "refs": config["refs"],
                "frameworks": config["frameworks"],
                "evidence": evidence,
                "seen": service["seen"] or "unknown date",
                "confidence": finding["confidence"],
                "stale": finding["stale"],
                "action": "Take this off the public internet: %s on %s port %s."
                % (finding["name"], service["ip"], service["port"]),
                "source": "scan",
            }
        )
    return items


def _checklist_findings(questions, answers):
    items = []
    for question in checklist.findings(questions, answers):
        unknown = question["answer"] == "unsure"
        items.append(
            {
                "title": question["ask"],
                "category": question["category"],
                "severity": question["severity"],
                "why": question["why"],
                "fix": question["fix"],
                "refs": question["refs"],
                "frameworks": question["frameworks"],
                "answer": checklist.LABELS[question["answer"]],
                "unknown": unknown,
                "action": question["fix"].split(". ")[0].rstrip(".") + ".",
                "source": "checklist",
            }
        )
    return items


def _rank(finding):
    # Severity leads, so a critical gap is never listed below a high one. Within a
    # severity: exposure, access, resilience, with scan evidence ahead of answers.
    return (
        SEVERITY_ORDER[finding["severity"]],
        CATEGORY_ORDER[finding["category"]],
        0 if finding["source"] == "scan" else 1,
    )


def _verdict(items, complete):
    critical = sum(1 for item in items if item["severity"] == "critical")
    if critical:
        return "urgent", "Act now: %d critical issue%s found" % (
            critical, "" if critical == 1 else "s")
    if items:
        return "action", "%d issue%s to fix" % (len(items), "" if len(items) == 1 else "s")
    if not complete:
        return "incomplete", "Check not finished"
    return "clear", "Nothing found in this data"


def build(site, scan, questions, answers):
    config = exposure.load_rules()
    items = _exposure_findings(scan, config) + _checklist_findings(questions, answers)
    items.sort(key=_rank)
    for position, item in enumerate(items, 1):
        item["number"] = position
        item["category_label"] = CATEGORY_LABELS[item["category"]]

    unanswered = [q for q in questions if q["id"] not in answers]
    complete = scan is not None and not unanswered
    state, headline = _verdict(items, complete)

    text = resources.files("otcheck").joinpath("rules/references.yaml").read_text("utf-8")
    references = yaml.safe_load(text)
    used = sorted({ref for item in items for ref in item["refs"]})
    count = lambda severity: sum(1 for i in items if i["severity"] == severity)
    return {
        "site": site,
        "scan": scan,
        "state": state,
        "headline": headline,
        "complete": complete,
        "findings": items,
        "first_actions": items[:3],
        "counts": {s: count(s) for s in SEVERITY_ORDER},
        "questions_total": len(questions),
        "questions_answered": len(questions) - len(unanswered),
        "unknown_count": sum(1 for i in items if i.get("unknown")),
        "stale_count": sum(1 for i in items if i.get("stale")),
        "references": [dict(references[ref], id=ref) for ref in used],
    }


def render(model):
    environment = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    template = resources.files("otcheck").joinpath("templates/report.html").read_text("utf-8")
    return environment.from_string(template).render(**model)


def write(model, folder):
    path = Path(folder) / "report.html"
    path.write_text(render(model), encoding="utf-8")
    return path
