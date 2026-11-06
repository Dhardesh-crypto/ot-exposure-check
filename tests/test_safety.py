"""The promises in SAFETY.md, enforced."""

import io
import json
import re
from pathlib import Path
from urllib.error import HTTPError

import pytest

from otcheck import cli, exposure, net

SITE_IP = "203.0.113.10"  # Reserved documentation address.


@pytest.fixture
def treat_as_real(monkeypatch):
    """Let live mode accept the reserved address, so no real IP appears in tests."""
    monkeypatch.setattr(exposure, "is_documentation", lambda address: False)


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def fake_opener(monkeypatch, handler):
    calls = []

    def open_url(request, timeout=None):
        calls.append(request.full_url)
        return handler(request.full_url)

    monkeypatch.setattr(net._opener, "open", open_url)
    return calls


def test_import_mode_opens_no_connections(no_network, site_dir, tmp_path):
    folder = site_dir("refrigeration-exposed")
    export = Path("fixtures/refrigeration-exposed/shodan-export.json")
    assert cli.main(["--dir", str(folder), "exposure", "--import", str(export)]) == 0
    assert cli.main(["--dir", str(folder), "report"]) == 0
    assert no_network == []


def test_live_mode_only_contacts_shodan(monkeypatch, no_network, treat_as_real):
    body = {"ip_str": SITE_IP, "data": [{"port": 502, "_shodan": {"module": "modbus"}}]}
    calls = fake_opener(monkeypatch, lambda url: FakeResponse(json.dumps(body).encode()))
    result = exposure.live_lookup([SITE_IP], "test-key", pause=0)
    assert len(result["findings"]) == 1
    assert [url.split("/")[2] for url in calls] == ["api.shodan.io"]
    assert no_network == []


@pytest.mark.parametrize(
    "url",
    [
        "https://203.0.113.10/",
        "https://198.51.100.20:502/",
        "http://api.shodan.io/shodan/host/203.0.113.10",
        "https://api.shodan.io.example.com/",
    ],
)
def test_unapproved_targets_are_refused(no_network, url):
    with pytest.raises(net.BlockedHost):
        net.get_json(url)
    assert no_network == []


def test_redirect_to_a_site_address_is_refused(monkeypatch):
    def redirect(url):
        raise HTTPError(url, 302, "Found", {"Location": "https://203.0.113.10/"}, None)

    fake_opener(monkeypatch, redirect)
    with pytest.raises(net.BlockedHost):
        net.get_json("https://rdap.org/ip/203.0.113.11")


def test_api_key_never_appears_in_errors(monkeypatch, treat_as_real):
    def fail(url):
        raise HTTPError(url, 401, "Unauthorized", {}, None)

    fake_opener(monkeypatch, fail)
    with pytest.raises(net.LookupFailed) as error:
        exposure.live_lookup([SITE_IP], "secret-test-key", pause=0)
    assert "secret-test-key" not in str(error.value)


def test_api_key_is_not_saved(monkeypatch, site_dir, treat_as_real):
    folder = site_dir("clean")
    data = json.loads((folder / "site.json").read_text())
    data["addresses"] = [SITE_IP]
    (folder / "site.json").write_text(json.dumps(data))
    monkeypatch.setenv("SHODAN_API_KEY", "secret-test-key")
    monkeypatch.setattr(exposure.time, "sleep", lambda s: None)
    fake_opener(monkeypatch, lambda url: FakeResponse(b'{"ip_str": "203.0.113.10", "data": []}'))
    assert cli.main(["--dir", str(folder), "exposure"]) == 0
    assert cli.main(["--dir", str(folder), "report"]) == 0
    for path in folder.iterdir():
        assert "secret-test-key" not in path.read_text()


def test_live_mode_refuses_simulated_addresses():
    with pytest.raises(exposure.SiteError):
        exposure.live_lookup(["203.0.113.10"], "key", pause=0)


def test_only_net_module_imports_network_libraries():
    package = Path(__file__).parent.parent / "otcheck"
    pattern = re.compile(r"^\s*(import|from)\s+(socket|urllib|http|requests|ssl)\b", re.M)
    offenders = [p.name for p in package.glob("*.py") if p.name != "net.py" and pattern.search(p.read_text())]
    assert offenders == []
