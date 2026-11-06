"""Guided questions about the basics a scan cannot see."""

import json
from importlib import resources
from pathlib import Path

import yaml

from .site import SiteError

LABELS = {"yes": "Yes", "no": "No", "unsure": "Don't know", "na": "Not applicable"}
SHORTCUTS = {"y": "yes", "n": "no", "d": "unsure", "x": "na"}


def load_questions(sector):
    root = resources.files("otcheck").joinpath("rules/checklist")
    questions = []
    packs = ["general"] if sector == "general" else ["general", sector]
    for pack in packs:
        text = root.joinpath("%s.yaml" % pack).read_text("utf-8")
        questions.extend(yaml.safe_load(text)["questions"])
    return questions


def validate(answer, question):
    if answer not in LABELS:
        return False
    return answer != "na" or bool(question.get("allow_na"))


def load_answers(folder):
    path = Path(folder) / "answers.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def save_answers(answers, folder):
    path = Path(folder) / "answers.json"
    path.write_text(json.dumps(answers, indent=2) + "\n", encoding="utf-8")


def import_answers(path, questions):
    """Load answers from a file, rejecting anything the question does not allow."""
    try:
        answers = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SiteError("Could not read answers from %s." % path) from None
    by_id = {q["id"]: q for q in questions}
    for key, value in answers.items():
        if key not in by_id or not validate(value, by_id[key]):
            raise SiteError("Invalid answer '%s' for '%s'." % (value, key))
    return answers


def run_interactive(questions, answers, folder, ask=input, say=print):
    """Ask each unanswered question, saving after every answer so it can resume."""
    remaining = [q for q in questions if q["id"] not in answers]
    if not remaining:
        say("All questions are answered. Use --restart to go through them again.")
        return answers
    say("%d of %d questions left. Press Ctrl+C at any time; your answers are saved.\n"
        % (len(remaining), len(questions)))
    for question in remaining:
        number = questions.index(question) + 1
        say("[%d/%d] %s" % (number, len(questions), question["ask"]))
        say("      %s" % question["help"])
        prompt = "      y = yes, n = no, d = don't know"
        prompt += ", x = not applicable: " if question.get("allow_na") else ": "
        while True:
            answer = SHORTCUTS.get(ask(prompt).strip().lower())
            if answer and validate(answer, question):
                break
            say("      Please choose one of the listed letters.")
        answers[question["id"]] = answer
        save_answers(answers, folder)
        say("")
    return answers


def findings(questions, answers):
    """Turn answers into findings. "Don't know" is a finding in its own right."""
    results = []
    for question in questions:
        answer = answers.get(question["id"])
        if answer in ("no", "unsure"):
            results.append(dict(question, answer=answer))
    return results
