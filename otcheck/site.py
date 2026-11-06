"""Site profile, address limits and the authorisation statement."""

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import net

SECTORS = ("general", "refrigeration", "water")
MAX_ADDRESSES = 256
STATEMENT = (
    "I am authorised by the organisation that runs this site to review the "
    "security of these addresses, and I believe the addresses belong to it."
)
# Reserved for documentation. Safe in simulated sites; they route nowhere.
DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


class SiteError(Exception):
    """A problem the user can fix, with a message written for them."""


@dataclass
class Site:
    name: str
    sector: str
    addresses: list
    authorised_by: str
    role: str
    statement: str = STATEMENT
    authorised_on: str = ""
    owners: dict = field(default_factory=dict)

    def save(self, folder):
        Path(folder).mkdir(parents=True, exist_ok=True)
        path = Path(folder) / "site.json"
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, folder):
        path = Path(folder) / "site.json"
        if not path.exists():
            raise SiteError("No site profile found. Run 'otcheck init' first.")
        return cls(**json.loads(path.read_text(encoding="utf-8")))


def is_documentation(address):
    ip = ipaddress.ip_address(address)
    return any(ip.version == n.version and ip in n for n in DOCUMENTATION_NETS)


def parse_addresses(values):
    """Expand addresses and ranges, enforcing the size cap and public-only rule."""
    found = []
    for value in values:
        try:
            network = ipaddress.ip_network(value.strip(), strict=False)
        except ValueError:
            raise SiteError("'%s' is not an IP address or range." % value) from None
        if network.num_addresses > MAX_ADDRESSES:
            raise SiteError(
                "%s is too large. This tool checks one site at a time, up to %d "
                "addresses." % (value, MAX_ADDRESSES)
            )
        hosts = [network.network_address] if network.num_addresses == 1 else network
        for ip in hosts:
            if not ip.is_global and not is_documentation(ip):
                raise SiteError(
                    "%s is a private or reserved address. Enter the public "
                    "addresses the internet sees." % ip
                )
            if str(ip) not in found:
                found.append(str(ip))
    if not found:
        raise SiteError("Enter at least one public IP address.")
    if len(found) > MAX_ADDRESSES:
        raise SiteError("That is more than %d addresses." % MAX_ADDRESSES)
    return found


def _registrant(data):
    for entity in data.get("entities", []):
        if "registrant" in entity.get("roles", []):
            for item in (entity.get("vcardArray") or [None, []])[1]:
                if item[0] == "fn" and item[3]:
                    return item[3]
    return None


def lookup_owner(address):
    """Ask the public internet registry who holds an address. Read-only, and it
    contacts the registry, not the address."""
    if is_documentation(address):
        return "Documentation address (simulated)"
    try:
        data = net.get_json("https://rdap.org/ip/%s" % address)
    except net.LookupFailed:
        return "Unknown (registry lookup failed)"
    if not data:
        return "Unknown (no registry record)"
    return _registrant(data) or data.get("name") or "Unknown (no name in record)"


def create_site(name, sector, addresses, authorised_by, role, owners=None):
    if sector not in SECTORS:
        raise SiteError("Sector must be one of: %s." % ", ".join(SECTORS))
    if not name.strip() or not authorised_by.strip() or not role.strip():
        raise SiteError("Site name, your name and your role are all required.")
    return Site(
        name=name.strip(),
        sector=sector,
        addresses=addresses,
        authorised_by=authorised_by.strip(),
        role=role.strip(),
        authorised_on=datetime.now(timezone.utc).date().isoformat(),
        owners=owners or {},
    )
