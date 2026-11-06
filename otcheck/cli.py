"""Command-line interface: init, exposure, checklist, report."""

import argparse
import os
import sys
from pathlib import Path

from . import __version__, checklist, engagement_cli, exposure, report
from .net import BlockedHost, LookupFailed
from .site import (MAX_ADDRESSES, SECTORS, STATEMENT, Site, SiteError, create_site,
                   lookup_owner, parse_addresses)


def _prompt(label, value=None):
    return value if value else input("%s: " % label).strip()


def cmd_init(args):
    print("Set up a site. This tool only reads scan data and your answers. "
          "It never connects to your equipment.\n")
    name = _prompt("Site name", args.name)
    sector = _prompt("Sector (%s)" % ", ".join(SECTORS), args.sector)
    raw = args.addresses or _prompt(
        "Public IP addresses, separated by commas (up to %d)" % MAX_ADDRESSES
    ).split(",")
    addresses = parse_addresses(raw)
    person = _prompt("Your name", args.authorised_by)
    role = _prompt("Your role", args.role)

    print("\nRegistered owner of each address:")
    owners = {}
    for address in addresses:
        owners[address] = lookup_owner(address)
        print("  %s: %s" % (address, owners[address]))
    print("\nCheck these names. If an address is not yours, stop now.\n")
    print(STATEMENT)
    confirmed = args.confirm_authorised or input("Type 'yes' to confirm: ").strip().lower() == "yes"
    if not confirmed:
        raise SiteError("Not confirmed, so nothing was saved.")
    create_site(name, sector, addresses, person, role, owners).save(args.dir)
    print("Saved to %s. Next: otcheck exposure" % args.dir)


def cmd_exposure(args):
    site = Site.load(args.dir)
    if args.import_file:
        result = exposure.import_file(args.import_file, site.addresses)
    else:
        result = exposure.live_lookup(site.addresses, os.environ.get("SHODAN_API_KEY"))
    exposure.save(result, args.dir)
    print("%d possible control system exposure(s), %d other service(s)."
          % (len(result["findings"]), len(result["other_services"])))
    if result["out_of_scope_skipped"]:
        print("Ignored %d record(s) for addresses outside this site."
              % result["out_of_scope_skipped"])
    print("Next: otcheck checklist")


def cmd_checklist(args):
    site = Site.load(args.dir)
    questions = checklist.load_questions(site.sector)
    if args.answers:
        answers = checklist.import_answers(args.answers, questions)
        checklist.save_answers(answers, args.dir)
    else:
        answers = {} if args.restart else checklist.load_answers(args.dir)
        answers = checklist.run_interactive(questions, answers, args.dir)
    print("%d of %d answered. Next: otcheck report" % (len(answers), len(questions)))


def cmd_report(args):
    site = Site.load(args.dir)
    questions = checklist.load_questions(site.sector)
    model = report.build(site, exposure.load(args.dir), questions, checklist.load_answers(args.dir))
    path = report.write(model, args.dir)
    print("%s. Report written to %s" % (model["headline"], path))


def parser():
    main = argparse.ArgumentParser(prog="otcheck", description=__doc__)
    main.add_argument("--version", action="version", version=__version__)
    main.add_argument("--dir", default="otcheck-site", type=Path,
                      help="folder for this site's data (default: otcheck-site)")
    commands = main.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="set up a site")
    init.add_argument("--name")
    init.add_argument("--sector", choices=SECTORS)
    init.add_argument("--addresses", nargs="+", help="public IP addresses or small ranges")
    init.add_argument("--authorised-by")
    init.add_argument("--role")
    init.add_argument("--confirm-authorised", action="store_true",
                      help="confirm the authorisation statement without a prompt")
    init.set_defaults(run=cmd_init)

    scan = commands.add_parser("exposure", help="check what the internet can see")
    scan.add_argument("--import", dest="import_file", metavar="FILE",
                      help="use a Shodan JSON export instead of the live API")
    scan.set_defaults(run=cmd_exposure)

    questions = commands.add_parser("checklist", help="answer the guided questions")
    questions.add_argument("--answers", metavar="FILE", help="load answers from a JSON file")
    questions.add_argument("--restart", action="store_true", help="start the questions again")
    questions.set_defaults(run=cmd_checklist)

    output = commands.add_parser("report", help="write report.html")
    output.set_defaults(run=cmd_report)

    engagement_cli.add_commands(commands)
    return main


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        args.run(args)
    except (SiteError, LookupFailed, BlockedHost) as error:
        print("Stopped: %s" % error, file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nStopped. Anything already answered is saved.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
