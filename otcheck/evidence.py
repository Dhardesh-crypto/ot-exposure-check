"""Checklist answers with a source, for consultant work."""

import json
from pathlib import Path

from . import checklist
from .site import SiteError

STATUSES = ("verified", "stated")


def record(question, answer, source, evidence="", status="stated"):
    if not checklist.validate(answer, question):
        raise SiteError("Invalid answer '%s' for '%s'." % (answer, question["id"]))
    if status not in STATUSES:
        raise SiteError("Status must be verified or stated.")
    if not source or not source.strip():
        raise SiteError("Say who gave the answer to '%s'." % question["id"])
    if status == "verified" and not evidence.strip():
        raise SiteError("A verified answer to '%s' needs evidence." % question["id"])
    return {"answer": answer, "source": source.strip(), "evidence": evidence.strip(), "status": status}


def load(folder):
    path = Path(folder) / "evidence.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save(records, folder):
    Path(folder, "evidence.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    checklist.save_answers({key: item["answer"] for key, item in records.items()}, folder)


def import_file(path, questions):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SiteError("Could not read answers from %s." % path) from None
    by_id = {question["id"]: question for question in questions}
    records = {}
    for key, item in data.items():
        if key not in by_id or not isinstance(item, dict):
            raise SiteError("Unknown or badly formed answer '%s'." % key)
        records[key] = record(
            by_id[key], item.get("answer"), item.get("source"),
            item.get("evidence", ""), item.get("status", "stated"),
        )
    return records
