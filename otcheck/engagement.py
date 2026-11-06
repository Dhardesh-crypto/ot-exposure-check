"""Consultant engagements: scope, authorisation dates and the activity log."""

import hashlib
import ipaddress
import json
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

from .site import SECTORS, Site, SiteError, parse_addresses

GENESIS = "0" * 64


def today():
    return datetime.now(timezone.utc).date()


def _date(value, label):
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        raise SiteError("%s must be a date like 2026-11-30." % label) from None


@dataclass
class Engagement:
    client: str
    consultant: str
    authoriser: str
    authorisation_ref: str
    start: str
    end: str
    sites: dict = field(default_factory=dict)
    closed: bool = False

    def save(self, folder):
        path = Path(folder) / "engagement.json"
        path.write_text(json.dumps(asdict(self), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, folder):
        path = Path(folder) / "engagement.json"
        if not path.exists():
            raise SiteError("No engagement found. Run 'otcheck engagement new' first.")
        return cls(**json.loads(path.read_text(encoding="utf-8")))

    def require_open(self):
        if self.closed:
            raise SiteError("This engagement is closed.")

    def require_active(self):
        """Collecting data needs a current authorisation. Writing up afterwards doesn't."""
        self.require_open()
        now = today()
        if now < _date(self.start, "Start"):
            raise SiteError("This engagement starts on %s. Authorisation isn't active yet." % self.start)
        if now > _date(self.end, "End"):
            raise SiteError(
                "Authorisation ended on %s. Get it extended in writing before collecting more data."
                % self.end
            )

    def site(self, slug):
        if slug not in self.sites:
            raise SiteError("'%s' isn't in this engagement's scope." % slug)
        return self.sites[slug]

    def as_site(self, slug):
        """Present an engagement site to the shared report engine."""
        record = self.site(slug)
        return Site(
            name=record["name"],
            sector=record["sector"],
            addresses=record["addresses"],
            authorised_by=self.consultant,
            role="Consultant for %s" % self.client,
            statement="Work carried out under authorisation %s from %s, valid %s to %s."
            % (self.authorisation_ref, self.authoriser, self.start, self.end),
            authorised_on=self.start,
        )


def create(client, consultant, authoriser, authorisation_ref, start, end):
    values = (client, consultant, authoriser, authorisation_ref)
    if not all(value and value.strip() for value in values):
        raise SiteError("Client, consultant, authoriser and authorisation reference are all required.")
    if _date(end, "End") < _date(start, "Start"):
        raise SiteError("The end date is before the start date.")
    return Engagement(*(value.strip() for value in values), start, end)


def slugify(name):
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not slug:
        raise SiteError("Give the site a name with letters or numbers.")
    return slug


def add_site(engagement, name, sector, addresses, contractor="", control_networks=()):
    if sector not in SECTORS:
        raise SiteError("Sector must be one of: %s." % ", ".join(SECTORS))
    slug = slugify(name)
    if slug in engagement.sites:
        raise SiteError("A site called '%s' already exists." % slug)
    networks = []
    for value in control_networks:
        try:
            networks.append(str(ipaddress.ip_network(value, strict=False)))
        except ValueError:
            raise SiteError("'%s' isn't a network range." % value) from None
    engagement.sites[slug] = {
        "name": name.strip(),
        "sector": sector,
        "addresses": parse_addresses(addresses),
        "contractor": contractor.strip(),
        "control_networks": networks,
    }
    return slug


def site_folder(folder, slug):
    path = Path(folder) / "sites" / slug
    path.mkdir(parents=True, exist_ok=True)
    return path


def inside_git_repo(folder):
    path = Path(folder).resolve()
    return any((parent / ".git").exists() for parent in [path, *path.parents])


# Activity log: each line carries a hash of the line before, so a later edit shows.

def _line_hash(previous, stamp, action, detail):
    text = "\t".join((previous, stamp, action, detail))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _clean(text):
    return re.sub(r"[\t\r\n]+", " ", str(text))


def log(folder, action, detail=""):
    path = Path(folder) / "activity.log"
    previous = GENESIS
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        if lines:
            previous = lines[-1].rsplit("\t", 1)[-1]
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    action, detail = _clean(action), _clean(detail)
    digest = _line_hash(previous, stamp, action, detail)
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\t".join((stamp, action, detail, digest)) + "\n")


def verify_log(folder):
    """Return the number of good lines, or raise if the chain has been altered."""
    path = Path(folder) / "activity.log"
    previous, count = GENESIS, 0
    if not path.exists():
        return 0
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split("\t")
        if len(parts) != 4 or _line_hash(previous, *parts[:3]) != parts[3]:
            raise SiteError("Activity log has been altered at line %d." % number)
        previous, count = parts[3], number
    return count


def summary(engagement, folder):
    return "\n".join(
        (
            "Client: %s" % engagement.client,
            "Consultant: %s" % engagement.consultant,
            "Authorisation: %s (%s to %s)" % (engagement.authorisation_ref, engagement.start, engagement.end),
            "Sites: %d" % len(engagement.sites),
            "Log entries: %d" % verify_log(folder),
            "Closed on: %s" % today().isoformat(),
        )
    ) + "\n"


def _check_safe_to_remove(folder):
    path = Path(folder).resolve()
    if not (path / "engagement.json").is_file():
        raise SiteError("That folder isn't an engagement.")
    if (path / ".git").exists() or path in (Path.home().resolve(), Path.cwd().resolve(), Path(path.anchor)):
        raise SiteError("Refusing to remove %s." % path)
    return path


def close(engagement, folder, mode, typed_client=""):
    """Archive or purge. A short summary with no findings is kept beside the folder."""
    engagement.require_open()
    if mode not in ("archive", "purge"):
        raise SiteError("Choose archive or purge.")
    if typed_client.strip() != engagement.client:
        raise SiteError("The client name didn't match, so nothing was changed.")
    path = _check_safe_to_remove(folder)
    note = path.with_name(path.name + "-closure.txt")
    log(path, "close", mode)
    note.write_text(summary(engagement, path), encoding="utf-8")
    if mode == "archive":
        engagement.closed = True
        engagement.save(path)
        return Path(shutil.make_archive(str(path), "zip", str(path)))
    shutil.rmtree(path)
    return note
