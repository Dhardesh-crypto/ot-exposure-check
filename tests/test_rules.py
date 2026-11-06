import pytest

from otcheck import checklist, exposure
from otcheck.report import CATEGORY_ORDER, SEVERITY_ORDER
from otcheck.site import SiteError, create_site, parse_addresses

IP = "203.0.113.10"


def banner(port=80, module="", product="", title="", ip=IP, ts="2026-11-02T00:00:00"):
    return {"ip_str": ip, "port": port, "timestamp": ts, "product": product,
            "http": {"title": title}, "_shodan": {"module": module}}


def one(item):
    result = exposure.analyse([item], [IP], "test")
    return result["findings"][0] if result["findings"] else None


@pytest.mark.parametrize(
    "module,rule",
    [("modbus", "modbus"), ("s7", "s7"), ("bacnet", "bacnet"), ("dnp3", "dnp3"),
     ("ethernetip", "ethernetip"), ("niagara-fox", "niagara-fox"), ("vnc", "vnc"),
     ("rdp", "rdp"), ("telnet", "telnet")],
)
def test_protocol_modules_are_detected(module, rule):
    assert one(banner(port=9999, module=module))["rule"] == rule


def test_web_panel_found_by_title():
    finding = one(banner(title="Refrigeration Plant Controller"))
    assert finding["rule"] == "control-panel" and finding["severity"] == "critical"


@pytest.mark.parametrize("port", [5900, 5905, 5910])
def test_vnc_port_range_from_the_advisory(port):
    assert one(banner(port=port))["rule"] == "vnc"


@pytest.mark.parametrize("title", ["Danfoss StoreView", "XWEB 300D", "Site Supervisor"])
def test_refrigeration_panels_named_in_public_research(title):
    assert one(banner(title=title))["rule"] == "control-panel"


def test_keywords_match_whole_words_only():
    assert one(banner(title="Schmidt Bakery")) is None


def test_port_alone_lowers_confidence_and_severity():
    finding = one(banner(port=502))
    assert finding["confidence"] == "port only" and finding["severity"] == "high"


def test_normal_website_is_not_a_finding():
    result = exposure.analyse([banner(port=443, product="nginx")], [IP], "test")
    assert result["findings"] == [] and len(result["other_services"]) == 1


def test_addresses_outside_the_site_are_ignored():
    item = banner(port=502, module="modbus", ip="198.51.100.9")
    result = exposure.analyse([item], [IP], "test")
    assert result["findings"] == [] and result["out_of_scope_skipped"] == 1
    assert result["addresses_without_data"] == [IP]


def test_old_scan_data_is_marked_stale():
    assert one(banner(module="vnc", ts="2020-01-01T00:00:00"))["stale"] is True


def test_raw_banner_text_is_not_kept():
    item = dict(banner(module="vnc"), data="admin password=hunter2")
    assert "hunter2" not in str(exposure.analyse([item], [IP], "test"))


def test_export_formats():
    assert len(exposure.parse_export('{"ip_str":"203.0.113.1","data":[{"port":1}]}')) == 1
    assert len(exposure.parse_export('[{"port":1},{"port":2}]')) == 2
    assert len(exposure.parse_export('{"port":1}\n{"port":2}\n')) == 2
    with pytest.raises(SiteError):
        exposure.parse_export("not json")


@pytest.mark.parametrize("value", ["10.0.0.1", "192.168.1.0/24", "127.0.0.1", "nonsense", "2001:db8::/64"])
def test_bad_addresses_are_rejected(value):
    with pytest.raises(SiteError):
        parse_addresses([value])


def test_small_range_expands():
    assert len(parse_addresses(["203.0.113.0/30"])) == 4


def test_total_address_cap_applies_across_entries():
    with pytest.raises(SiteError):
        parse_addresses(["203.0.113.0/24", "198.51.100.0/24"])


def test_site_requires_named_person():
    with pytest.raises(SiteError):
        create_site("Site", "water", [IP], " ", "IT")


@pytest.mark.parametrize("sector", ["general", "refrigeration", "water"])
def test_question_packs_are_complete(sector):
    questions = checklist.load_questions(sector)
    ids = [q["id"] for q in questions]
    assert len(ids) == len(set(ids))
    for q in questions:
        assert q["category"] in CATEGORY_ORDER and q["severity"] in SEVERITY_ORDER
        for key in ("ask", "help", "why", "fix", "refs", "frameworks"):
            assert q[key], (q["id"], key)


def test_unsure_is_a_finding_and_na_needs_permission():
    questions = checklist.load_questions("general")
    answers = {q["id"]: "yes" for q in questions}
    answers["backups"] = "unsure"
    assert [f["id"] for f in checklist.findings(questions, answers)] == ["backups"]
    backups = next(q for q in questions if q["id"] == "backups")
    mfa = next(q for q in questions if q["id"] == "mfa")
    assert not checklist.validate("na", backups) and checklist.validate("na", mfa)


def test_interactive_checklist_resumes(tmp_path):
    questions = checklist.load_questions("general")[:3]
    replies = iter(["y", "?", "n"])

    def ask(prompt):
        reply = next(replies, None)
        if reply is None:
            raise KeyboardInterrupt
        return reply

    with pytest.raises(KeyboardInterrupt):
        checklist.run_interactive(questions, {}, tmp_path, ask=ask, say=lambda t: None)
    saved = checklist.load_answers(tmp_path)
    assert saved == {questions[0]["id"]: "yes", questions[1]["id"]: "no"}
    final = checklist.run_interactive(questions, saved, tmp_path, ask=lambda p: "d", say=lambda t: None)
    assert final[questions[2]["id"]] == "unsure"
