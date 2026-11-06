# otcheck

A read-only check for industrial sites, written for site IT staff. No security background or on-site hardware is needed.

It answers three questions:

1. Can the internet see our control systems?
2. Do we have the basic protections in place?
3. What should we fix first?

**otcheck never connects to your equipment.** It reads existing scan data and your answers. See [SAFETY.md](SAFETY.md).

## Why it exists

Government advisories describe attackers reaching control screens through internet exposure, VNC and default passwords. These are basic gaps that a site can find and close itself.

## Before you start

- Python 3.9 or newer
- Your site's public IP addresses (your internet provider or firewall will show them)
- Permission to review the site
- Optional: a Shodan API key, or a Shodan JSON export of your addresses

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install .
```

## Use it

Set up the site. Sectors are `general`, `refrigeration` and `water`.

```bash
.venv/bin/otcheck init
```

Check internet exposure, with your own Shodan key:

```bash
export SHODAN_API_KEY=your-key
.venv/bin/otcheck exposure
```

Or use a Shodan export you already have:

```bash
.venv/bin/otcheck exposure --import my-export.json
```

Answer the questions. You can stop at any time and carry on later. "Don't know" is a fair answer: it goes in the report as something to find out.

```bash
.venv/bin/otcheck checklist
```

Write the report to `otcheck-site/report.html`. Open it in a browser, or print it.

```bash
.venv/bin/otcheck report
```

## Reading the result

- **Critical:** act now, starting with the "Do these first" list.
- **Nothing found in this data:** this covers only the data checked. It does not mean the site is safe. Read "What this check cannot see".

Before you disconnect anything, talk to the operator and vendor. Some alarms and monitoring may use that connection.

The report lists your site's weaknesses, so store and share it carefully. Your site data stays in `otcheck-site/` on your computer.

## Try it on a simulated site

```bash
.venv/bin/otcheck --dir demo init --name "Demo store" --sector refrigeration --addresses 203.0.113.10 203.0.113.11 --authorised-by "Your name" --role "Site IT" --confirm-authorised
```

```bash
.venv/bin/otcheck --dir demo exposure --import fixtures/refrigeration-exposed/shodan-export.json
```

```bash
.venv/bin/otcheck --dir demo checklist --answers fixtures/refrigeration-exposed/answers.json
```

```bash
.venv/bin/otcheck --dir demo report
```

## For developers

```bash
.venv/bin/pip install -e ".[dev]"
```

```bash
.venv/bin/python -m pytest
```

Detection rules and questions are data files in `otcheck/rules/`. All fixtures are simulated and use reserved documentation addresses.

## For security consultants

`otcheck engagement` covers several client sites, authorisation dates, evidence, offline Zeek or Malcolm logs, a client report and retests. See [CONSULTANTS.md](CONSULTANTS.md).

## Status

Early version. It has only been tested on simulated data, and live Shodan and registry lookups have not yet been run against the real services. It does not replace a professional assessment.
