"""The only code in otcheck that touches the network.

Every request goes through get_json(), which refuses any host that is not a
known lookup service. Site addresses are never on that list, so the tool cannot
connect to the systems it reports on, even through a redirect.
"""

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ALLOWED_HOSTS = frozenset(
    {
        "api.shodan.io",
        "rdap.org",
        "rdap.arin.net",
        "rdap.db.ripe.net",
        "rdap.apnic.net",
        "rdap.lacnic.net",
        "rdap.afrinic.net",
    }
)
REDIRECTS = (301, 302, 303, 307, 308)


class BlockedHost(Exception):
    """A request was aimed at something other than an approved lookup service."""


class LookupFailed(Exception):
    """A lookup service could not answer. The message never contains the URL,
    because Shodan URLs carry the API key."""


class _NoAutoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = build_opener(_NoAutoRedirect)


def check_url(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise BlockedHost("refused to contact %s" % (parts.hostname or "unknown host"))
    return parts.hostname


def get_json(url, max_redirects=3):
    """Return parsed JSON, or None when the service has no record (HTTP 404)."""
    for _ in range(max_redirects + 1):
        host = check_url(url)
        request = Request(
            url, headers={"Accept": "application/json", "User-Agent": "otcheck/0.1"}
        )
        try:
            with _opener.open(request, timeout=20) as response:
                return json.load(response)
        except HTTPError as error:
            if error.code in REDIRECTS and error.headers.get("Location"):
                url = urljoin(url, error.headers["Location"])
                continue
            if error.code == 404:
                return None
            raise LookupFailed("%s returned HTTP %s" % (host, error.code)) from None
        except (URLError, OSError, ValueError):
            raise LookupFailed("could not get an answer from %s" % host) from None
    raise LookupFailed("too many redirects")
