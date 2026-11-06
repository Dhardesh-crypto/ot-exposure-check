import shutil
import socket
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if anything tries to open a network connection."""
    attempts = []

    def refuse(self, address):
        attempts.append(address)
        raise AssertionError("network connection attempted: %s" % (address,))

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: refuse(None, a))
    return attempts


@pytest.fixture
def site_dir(tmp_path):
    """Copy a simulated site's profile into a temporary working folder."""

    def make(name):
        folder = tmp_path / name
        folder.mkdir()
        shutil.copy(FIXTURES / name / "site.json", folder / "site.json")
        return folder

    return make
