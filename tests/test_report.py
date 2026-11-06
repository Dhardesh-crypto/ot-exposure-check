import re
from pathlib import Path

import pytest

from otcheck import checklist, cli, exposure, report
from otcheck.site import Site

FIXTURES = Path(__file__).parent.parent / "fixtures"


def run_site(name, site_dir):
    folder = site_dir(name)
    source = FIXTURES / name
    assert cli.main(["--dir", str(folder), "exposure", "--import", str(source / "shodan-export.json")]) == 0
    assert cli.main(["--dir", str(folder), "checklist", "--answers", str(source / "answers.json")]) == 0
    assert cli.main(["--dir", str(folder), "report"]) == 0
    site = Site.load(folder)
    questions = checklist.load_questions(site.sector)
    model = report.build(site, exposure.load(folder), questions, checklist.load_answers(folder))
    return model, (folder / "report.html").read_text()


def test_refrigeration_site(site_dir):
    model, html = run_site("refrigeration-exposed", site_dir)
    assert model["state"] == "urgent"
    titles = [f["title"] for f in model["findings"]]
    assert any("VNC" in t and "203.0.113.10" in t for t in titles)
    assert any("Web control panel" in t for t in titles)
    assert model["scan"]["out_of_scope_skipped"] == 1
    assert "198.51.100.99" not in html
    assert model["unknown_count"] == 2
    assert "separate device" in html


def test_water_site(site_dir):
    model, html = run_site("water-exposed", site_dir)
    assert model["state"] == "urgent"
    assert model["counts"]["critical"] == 2  # Modbus and DNP3
    rdp = next(f for f in model["findings"] if "Remote Desktop" in f["title"])
    assert rdp["severity"] == "high" and rdp["stale"] is True
    assert "over 30 days old" in html


def test_clean_site_never_claims_safety(site_dir):
    model, html = run_site("clean", site_dir)
    assert model["state"] == "clear" and model["findings"] == []
    assert "Nothing found in this data" in html
    assert "does not show that the site is safe" in html
    assert "Other visible services" in html
    assert "192.0.2.31" in html  # No scan record must be disclosed, not read as closed.
    assert not re.search(r"you are (secure|safe)|site is secure|no vulnerabilities", html, re.I)


@pytest.mark.parametrize("name", ["refrigeration-exposed", "water-exposed", "clean"])
def test_every_report_keeps_its_warnings(name, site_dir):
    _, html = run_site(name, site_dir)
    assert "Confidential" in html
    assert "What this check cannot see" in html
    assert "not a penetration test" in html
    assert "Sam Example" in html and "I am authorised" in html
    assert "<script" not in html and "http://" not in html  # Self-contained, no remote loads.


def test_findings_rank_by_severity_then_category(site_dir):
    model, html = run_site("refrigeration-exposed", site_dir)
    ranks = [(report.SEVERITY_ORDER[f["severity"]], report.CATEGORY_ORDER[f["category"]])
             for f in model["findings"]]
    assert ranks == sorted(ranks)
    assert model["findings"][0]["source"] == "scan"
    assert [f["severity"] for f in model["first_actions"]] == ["critical"] * 3
    assert "Change every default password, starting with anything reachable from outside." in html


def test_unfinished_check_is_never_clear(site_dir):
    folder = site_dir("clean")
    assert cli.main(["--dir", str(folder), "report"]) == 0
    html = (folder / "report.html").read_text()
    assert "Check not finished" in html and "Nothing found in this data" not in html
    assert "Not done:" in html


def test_partial_checklist_warns_even_with_findings(site_dir):
    site = Site.load(site_dir("clean"))
    questions = checklist.load_questions(site.sector)
    model = report.build(site, None, questions, {"mfa": "no"})
    assert model["state"] == "action" and model["complete"] is False
    assert "This check is not finished" in report.render(model)


def test_hostile_scan_text_is_escaped(site_dir):
    folder = site_dir("clean")
    site = Site.load(folder)
    banner = {"ip_str": site.addresses[0], "port": 80, "timestamp": "2026-11-02T00:00:00",
              "product": "<script>alert(1)</script>", "_shodan": {"module": "vnc"}}
    other = dict(banner, port=81, _shodan={"module": "http"})
    scan = exposure.analyse([banner, other], site.addresses, "test")
    html = report.render(report.build(site, scan, checklist.load_questions(site.sector), {}))
    assert "<script" not in html and "&lt;script&gt;" in html
