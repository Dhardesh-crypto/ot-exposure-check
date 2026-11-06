import csv
import io
import json
import shutil
from datetime import date
from pathlib import Path

import pytest

from otcheck import cli, deliverable, engagement, inventory, matching, net
from otcheck.site import SiteError

F = Path(__file__).parent.parent / "fixtures" / "engagement"
CLIENT = "Example Retail Group (simulated)"


@pytest.fixture
def run(tmp_path, monkeypatch):
    folder = tmp_path / "work"
    monkeypatch.setattr(engagement, "today", lambda: date(2026, 11, 10))
    monkeypatch.setattr(deliverable, "today", lambda: date(2026, 11, 10))

    def command(*args):
        return cli.main(["engagement", "--folder", str(folder), *[str(a) for a in args]])

    command.folder = folder
    return command


@pytest.fixture
def setup(run):
    assert run("new", "--client", CLIENT, "--consultant", "Sam Example", "--authoriser", "Alex Example",
               "--authorisation-ref", "AUTH-001", "--start", "2026-11-01", "--end", "2026-11-30") == 0
    sites = [("North Store", "refrigeration", "203.0.113.40", "Example Cooling Ltd", []),
             ("South Store", "refrigeration", "203.0.113.50", "Example Cooling Ltd", []),
             ("Water Works", "water", "198.51.100.60", "", ["10.10.0.0/16"])]
    for name, sector, address, contractor, networks in sites:
        extra = ["--contractor", contractor] if contractor else []
        extra += ["--control-networks", *networks] if networks else []
        assert run("add-site", "--name", name, "--sector", sector, "--addresses", address, *extra) == 0
    for slug, prefix in (("north-store", "north"), ("south-store", "south"), ("water-works", "water")):
        assert run("exposure", "--site", slug, "--import", F / ("%s-scan.json" % prefix)) == 0
        assert run("checklist", "--site", slug, "--answers", F / ("%s-answers.json" % prefix)) == 0
    assert run("import-traffic", "--site", "water-works", F / "water-conn.log", F / "water-malcolm.jsonl") == 0
    assert run("import-assets", "--site", "north-store", F / "north-assets.csv") == 0
    assert run("match", "--site", "north-store", "--kev", F / "kev-simulated.json") == 0
    return run


def model(run):
    return deliverable.build(engagement.Engagement.load(run.folder), run.folder)


def test_full_engagement_report(setup):
    assert setup("report") == 0
    data = model(setup)
    assert data["counts"]["critical"] >= 4
    assert data["complete"] is True
    html = (setup.folder / "deliverables/client-report.html").read_text()
    for text in ("North Store", "Water Works", "AUTH-001", "Confidential", "What this review cannot see",
                 "not a penetration test", "Example Cooling Ltd", "Verified, from Site lead interview"):
        assert text in html
    assert "<script" not in html


def test_patterns_across_sites(setup):
    patterns = model(setup)["patterns"]
    assert patterns["contractors"][0]["name"] == "Example Cooling Ltd"
    assert len(patterns["contractors"][0]["sites"]) == 2
    titles = [item["title"] for item in patterns["repeated"]]
    assert "VNC remote screen visible from the internet" in titles
    assert any("default passwords" in title for title in titles)


def test_scope_is_enforced_for_scan_data(setup):
    south = json.loads((setup.folder / "sites/south-store/exposure.json").read_text())
    assert south["out_of_scope_skipped"] == 1
    assert "198.51.100.99" not in (setup.folder / "sites/south-store/exposure.json").read_text().replace(
        '"out_of_scope_skipped": 1', "")


def test_unknown_site_is_refused(setup):
    assert setup("exposure", "--site", "elsewhere", "--import", F / "north-scan.json") == 1


@pytest.mark.parametrize("day", [date(2026, 10, 31), date(2026, 12, 1)])
def test_collection_refused_outside_dates(setup, monkeypatch, day):
    monkeypatch.setattr(engagement, "today", lambda: day)
    assert setup("exposure", "--site", "north-store", "--import", F / "north-scan.json") == 1
    assert setup("import-assets", "--site", "north-store", F / "north-assets.csv") == 1
    assert setup("add-site", "--name", "New", "--sector", "water", "--addresses", "203.0.113.70") == 1


def test_report_can_be_written_after_the_end_date(setup, monkeypatch):
    monkeypatch.setattr(engagement, "today", lambda: date(2026, 12, 5))
    assert setup("report") == 0


def test_engagement_needs_valid_dates_and_authoriser():
    with pytest.raises(SiteError):
        engagement.create("C", "S", "A", "R", "2026-12-01", "2026-11-01")
    with pytest.raises(SiteError):
        engagement.create("C", "S", " ", "R", "2026-11-01", "2026-12-01")


def test_activity_log_only_grows_and_shows_tampering(setup):
    path = setup.folder / "activity.log"
    before = path.read_text()
    assert setup("report") == 0
    assert path.read_text().startswith(before)
    assert engagement.verify_log(setup.folder) == before.count("\n") + 1
    path.write_text(before.replace("AUTH-001", "AUTH-999"))
    with pytest.raises(SiteError):
        engagement.verify_log(setup.folder)
    assert setup("verify-log") == 1


def test_deleted_log_line_is_detected(setup):
    path = setup.folder / "activity.log"
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    with pytest.raises(SiteError):
        engagement.verify_log(setup.folder)


def test_evidence_rules(setup):
    question = {"id": "x"}
    with pytest.raises(SiteError):
        from otcheck import evidence
        evidence.record(question, "yes", "Sam", "", "verified")
    with pytest.raises(SiteError):
        evidence.record(question, "yes", " ", "note", "stated")


def test_stated_answers_are_disclosed(setup):
    assert setup("report") == 0
    assert "stated but not verified" in (setup.folder / "deliverables/client-report.html").read_text()


def test_traffic_findings():
    flows, skipped = inventory.parse_log((F / "water-conn.log").read_text())
    assert skipped == 1 and len(flows) == 4
    result = inventory.analyse(flows, ["10.10.0.0/16"], skipped)
    keys = [item["key"] for item in result["findings"]]
    assert "traffic:inbound:10.10.0.12:20000" in keys
    assert "traffic:crossing:10.20.0.5:10.10.0.11:502" in keys
    assert "traffic:outbound:10.10.0.11" in keys
    assert {item["ip"] for item in result["devices"]} == {"10.10.0.11", "10.10.0.12"}


def test_malcolm_nested_records_are_read():
    flows, _ = inventory.parse_log((F / "water-malcolm.jsonl").read_text())
    assert flows[0]["port"] == 44818 and flows[0]["source"] == "10.20.0.9"


def test_logs_with_no_records_are_refused(tmp_path):
    path = tmp_path / "empty.log"
    path.write_text("nonsense\n")
    with pytest.raises(SiteError):
        inventory.import_logs([path], [])


def test_raw_logs_are_not_kept(setup):
    stored = (setup.folder / "sites/water-works/inventory.json").read_text()
    assert "uid" not in stored and '"flows"' not in stored


def test_lifecycle_and_firmware_matching():
    assets = inventory.import_assets(F / "north-assets.csv")
    kev = json.loads((F / "kev-simulated.json").read_text())
    results = matching.match(assets, kev)
    titles = " ".join(item["title"] for item in results)
    assert "AK-SM 800 at 10.1.0.5 appears to be end of life" in titles
    assert "10.1.0.6 has firmware 4.2.0" in titles
    assert "10.1.0.7" not in titles  # 4.3.1 is the fixed version
    assert "CVE-0000-0001" in titles
    assert all(item["title"].startswith("Check:") for item in results)


def test_model_800a_is_not_treated_as_800():
    assets = [{"ip": "10.1.0.6", "make": "Danfoss", "model": "AK-SM 800A", "firmware": "9.0"}]
    assert matching.match(assets) == []


def test_unknown_firmware_still_prompts_a_check():
    assets = [{"ip": "10.1.0.6", "make": "Danfoss", "model": "AK-SM 800A", "firmware": ""}]
    assert "unknown firmware" in matching.match(assets)[0]["title"]


def test_retest(setup):
    assert setup("report") == 0
    baseline = setup.folder.parent / "baseline.json"
    shutil.copy(setup.folder / "deliverables/findings.json", baseline)
    assert setup("exposure", "--site", "north-store", "--import", F / "north-retest.json") == 0
    assert setup("exposure", "--site", "south-store", "--import", F / "south-retest.json") == 0
    assert setup("compare", "--baseline", baseline) == 0
    result = json.loads((setup.folder / "retest.json").read_text())
    assert any("VNC" in item["title"] and "203.0.113.40" in item["title"] for item in result["not_found"])
    assert any("203.0.113.50" in item["title"] and "VNC" in item["title"] for item in result["still_open"])
    assert any("Remote Desktop" in item["title"] for item in result["new"])
    assert setup("report") == 0
    html = (setup.folder / "deliverables/client-report.html").read_text()
    assert "No longer found" in html and "isn't proof of a fix" in html


def test_findings_register_blocks_formulas(setup):
    assert deliverable.safe_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)"
    assert deliverable.safe_cell("@cmd") == "'@cmd"
    assert deliverable.safe_cell("normal") == "normal"
    hostile = {"id": "=1+1", "site": "+x", "severity": "high", "category_label": "Access",
               "title": "-y", "evidence_label": "@z", "fix": "ok"}
    row = list(csv.reader(io.StringIO(deliverable.register_csv([hostile]))))[1]
    assert all(not cell.startswith(("=", "+", "-", "@")) for cell in row)


def test_hostile_evidence_is_escaped(setup):
    path = setup.folder / "sites/north-store/evidence.json"
    records = json.loads(path.read_text())
    records["default-passwords"]["evidence"] = "<script>alert(1)</script>"
    path.write_text(json.dumps(records))
    html = deliverable.render(model(setup))
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_offline_commands_open_no_connections(setup, no_network):
    assert setup("import-traffic", "--site", "water-works", F / "water-conn.log") == 0
    assert setup("match", "--site", "north-store", "--kev", F / "kev-simulated.json") == 0
    assert setup("report") == 0
    assert no_network == []


def test_kev_download_only_contacts_cisa(monkeypatch):
    calls = []
    monkeypatch.setattr(net, "get_json", lambda url: calls.append(url) or {"vulnerabilities": []})
    matching.fetch_kev()
    assert net.check_url(calls[0]) == "www.cisa.gov"


def test_purge_removes_only_the_named_engagement(setup, monkeypatch):
    neighbour = setup.folder.parent / "other"
    neighbour.mkdir()
    (neighbour / "keep.txt").write_text("keep")
    item = engagement.Engagement.load(setup.folder)
    with pytest.raises(SiteError):
        engagement.close(item, setup.folder, "purge", "wrong name")
    assert setup.folder.exists()
    note = engagement.close(item, setup.folder, "purge", CLIENT)
    assert not setup.folder.exists() and (neighbour / "keep.txt").exists()
    assert "AUTH-001" in note.read_text() and "VNC" not in note.read_text()


def test_purge_refuses_folders_that_are_not_engagements(tmp_path):
    item = engagement.create(CLIENT, "S", "A", "R", "2026-11-01", "2026-11-30")
    (tmp_path / "keep.txt").write_text("keep")
    with pytest.raises(SiteError):
        engagement.close(item, tmp_path, "purge", CLIENT)
    assert (tmp_path / "keep.txt").exists()


def test_purge_refuses_git_repositories(setup):
    item = engagement.Engagement.load(setup.folder)
    (setup.folder / ".git").mkdir()
    with pytest.raises(SiteError):
        engagement.close(item, setup.folder, "purge", CLIENT)
    assert setup.folder.exists()


def test_archive_closes_the_engagement(setup):
    item = engagement.Engagement.load(setup.folder)
    archive = engagement.close(item, setup.folder, "archive", CLIENT)
    assert archive.exists() and archive.suffix == ".zip"
    assert setup("exposure", "--site", "north-store", "--import", F / "north-scan.json") == 1


def test_warns_inside_git_repo(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "client").mkdir()
    assert engagement.inside_git_repo(tmp_path / "client") is True


def test_templates_copy_and_carry_the_legal_note(tmp_path):
    out = tmp_path / "templates"
    assert cli.main(["engagement", "templates", "--out", str(out)]) == 0
    assert len(list(out.glob("*.md"))) == 6
    assert "lawyer" in (out / "01-authorisation-letter.md").read_text()
    assert "Scanning, probing or testing" in (out / "01-authorisation-letter.md").read_text()
