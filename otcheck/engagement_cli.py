"""The 'otcheck engagement' commands for security consultants."""

import os
import shutil
from importlib import resources
from pathlib import Path

from . import checklist, deliverable, engagement, evidence, exposure, inventory, matching
from .site import SECTORS, SiteError


def _load(args):
    return engagement.Engagement.load(args.folder)


def cmd_new(args):
    item = engagement.create(args.client, args.consultant, args.authoriser, args.authorisation_ref,
                             args.start, args.end)
    folder = Path(args.folder)
    if (folder / "engagement.json").exists():
        raise SiteError("That folder already has an engagement.")
    folder.mkdir(parents=True, exist_ok=True)
    item.save(folder)
    engagement.log(folder, "new", "authorisation %s" % item.authorisation_ref)
    if engagement.inside_git_repo(folder):
        print("Warning: this folder is inside a git repository. Keep client data out of it.")
    print("Engagement created in %s. Keep it on encrypted storage." % folder)


def cmd_add_site(args):
    item = _load(args)
    item.require_active()
    slug = engagement.add_site(item, args.name, args.sector, args.addresses, args.contractor or "",
                               args.control_networks or ())
    item.save(args.folder)
    engagement.log(args.folder, "add-site", slug)
    print("Added site '%s'." % slug)


def cmd_exposure(args):
    item = _load(args)
    item.require_active()
    addresses = item.site(args.site)["addresses"]
    if args.import_file:
        result = exposure.import_file(args.import_file, addresses)
    else:
        result = exposure.live_lookup(addresses, os.environ.get("SHODAN_API_KEY"))
    exposure.save(result, engagement.site_folder(args.folder, args.site))
    engagement.log(args.folder, "exposure", "%s: %s" % (args.site, result["source"]))
    print("%s: %d exposure finding(s), %d out-of-scope record(s) ignored."
          % (args.site, len(result["findings"]), result["out_of_scope_skipped"]))


def cmd_checklist(args):
    item = _load(args)
    item.require_active()
    record = item.site(args.site)
    path = engagement.site_folder(args.folder, args.site)
    questions = checklist.load_questions(record["sector"])
    if args.answers:
        records = evidence.import_file(args.answers, questions)
    else:
        if not args.source:
            raise SiteError("Use --source to say who is answering, or --answers with a file.")
        records = evidence.load(path)
        answers = {key: entry["answer"] for key, entry in records.items()}
        answers = checklist.run_interactive(questions, answers, path)
        by_id = {question["id"]: question for question in questions}
        for key, answer in answers.items():
            if key not in records:
                records[key] = evidence.record(by_id[key], answer, args.source)
    evidence.save(records, path)
    engagement.log(args.folder, "checklist", "%s: %d answers" % (args.site, len(records)))
    print("%s: %d of %d answered." % (args.site, len(records), len(questions)))


def cmd_import_traffic(args):
    item = _load(args)
    item.require_active()
    record = item.site(args.site)
    result = inventory.import_logs(args.files, record["control_networks"])
    inventory.save(result, "inventory.json", engagement.site_folder(args.folder, args.site))
    engagement.log(args.folder, "import-traffic", "%s: %d records" % (args.site, result["flows_read"]))
    print("%s: %d control device(s), %d finding(s), %d unreadable record(s) skipped."
          % (args.site, len(result["devices"]), len(result["findings"]), result["rows_skipped"]))


def cmd_import_assets(args):
    item = _load(args)
    item.require_active()
    item.site(args.site)
    assets = inventory.import_assets(args.file)
    inventory.save(assets, "assets.json", engagement.site_folder(args.folder, args.site))
    engagement.log(args.folder, "import-assets", "%s: %d assets" % (args.site, len(assets)))
    print("%s: %d asset(s) imported." % (args.site, len(assets)))


def cmd_match(args):
    item = _load(args)
    item.require_open()
    item.site(args.site)
    kev = None
    if args.update_kev:
        kev = matching.fetch_kev()
        inventory.save(kev, "kev.json", args.folder)
    elif args.kev:
        kev = inventory.load(Path(args.kev).name, Path(args.kev).parent)
        if kev is None:
            raise SiteError("Could not read %s." % args.kev)
    else:
        kev = inventory.load("kev.json", args.folder)
    path = engagement.site_folder(args.folder, args.site)
    results = matching.match(inventory.load("assets.json", path, []), kev)
    inventory.save(results, "matches.json", path)
    engagement.log(args.folder, "match", "%s: %d results" % (args.site, len(results)))
    print("%s: %d item(s) to check." % (args.site, len(results)))


def cmd_compare(args):
    item = _load(args)
    item.require_open()
    model = deliverable.build(item, args.folder)
    result = deliverable.compare(args.baseline, model["findings"])
    inventory.save(result, "retest.json", args.folder)
    engagement.log(args.folder, "compare", args.baseline)
    print("%d no longer found, %d still open, %d new."
          % (len(result["not_found"]), len(result["still_open"]), len(result["new"])))


def cmd_report(args):
    item = _load(args)
    item.require_open()
    model = deliverable.build(item, args.folder)
    out = deliverable.write(model, args.folder)
    engagement.log(args.folder, "report", "%d findings" % len(model["findings"]))
    print("Client report and findings register written to %s." % out)


def cmd_verify_log(args):
    print("Activity log intact: %d entries." % engagement.verify_log(args.folder))


def cmd_close(args):
    item = _load(args)
    print(engagement.summary(item, args.folder))
    verb = "permanently delete" if args.mode == "purge" else "archive"
    typed = input("Type the client name to %s this engagement: " % verb)
    result = engagement.close(item, args.folder, args.mode, typed)
    print("Done. See %s." % result)


def cmd_templates(args):
    target = Path(args.out)
    target.mkdir(parents=True, exist_ok=True)
    source = resources.files("otcheck").joinpath("templates/consultant")
    copied = 0
    for entry in source.iterdir():
        if entry.name.endswith(".md"):
            destination = target / entry.name
            if destination.exists():
                raise SiteError("%s already exists." % destination)
            with resources.as_file(entry) as path:
                shutil.copy(path, destination)
            copied += 1
    print("%d templates copied to %s. Have a lawyer review them before use." % (copied, target))


def add_commands(commands):
    root = commands.add_parser("engagement", help="consultant work across client sites")
    root.add_argument("--folder", default="otcheck-engagement", help="engagement folder")
    group = root.add_subparsers(dest="engagement_command", required=True)

    new = group.add_parser("new", help="start an engagement")
    new.add_argument("--client", required=True)
    new.add_argument("--consultant", required=True)
    new.add_argument("--authoriser", required=True, help="the person at the client who authorised this")
    new.add_argument("--authorisation-ref", required=True, help="reference of the signed letter")
    new.add_argument("--start", required=True, help="YYYY-MM-DD")
    new.add_argument("--end", required=True, help="YYYY-MM-DD")
    new.set_defaults(run=cmd_new)

    site = group.add_parser("add-site", help="add a site to the scope")
    site.add_argument("--name", required=True)
    site.add_argument("--sector", required=True, choices=SECTORS)
    site.add_argument("--addresses", required=True, nargs="+")
    site.add_argument("--contractor")
    site.add_argument("--control-networks", nargs="*", help="internal control network ranges")
    site.set_defaults(run=cmd_add_site)

    scan = group.add_parser("exposure", help="check a site's internet exposure")
    scan.add_argument("--site", required=True)
    scan.add_argument("--import", dest="import_file", metavar="FILE")
    scan.set_defaults(run=cmd_exposure)

    questions = group.add_parser("checklist", help="record answers with their source")
    questions.add_argument("--site", required=True)
    questions.add_argument("--answers", metavar="FILE")
    questions.add_argument("--source", help="who is answering, for interactive use")
    questions.set_defaults(run=cmd_checklist)

    traffic = group.add_parser("import-traffic", help="read offline Zeek or Malcolm logs")
    traffic.add_argument("--site", required=True)
    traffic.add_argument("files", nargs="+")
    traffic.set_defaults(run=cmd_import_traffic)

    assets = group.add_parser("import-assets", help="read a CSV asset list")
    assets.add_argument("--site", required=True)
    assets.add_argument("file")
    assets.set_defaults(run=cmd_import_assets)

    match = group.add_parser("match", help="compare assets with support and exploited lists")
    match.add_argument("--site", required=True)
    match.add_argument("--kev", metavar="FILE", help="a saved copy of CISA's list")
    match.add_argument("--update-kev", action="store_true", help="download CISA's list")
    match.set_defaults(run=cmd_match)

    output = group.add_parser("report", help="write the client report and findings register")
    output.set_defaults(run=cmd_report)

    retest = group.add_parser("compare", help="compare with an earlier findings.json")
    retest.add_argument("--baseline", required=True)
    retest.set_defaults(run=cmd_compare)

    verify = group.add_parser("verify-log", help="check the activity log hasn't been altered")
    verify.set_defaults(run=cmd_verify_log)

    close = group.add_parser("close", help="archive or permanently delete client data")
    close.add_argument("mode", choices=("archive", "purge"))
    close.set_defaults(run=cmd_close)

    templates = group.add_parser("templates", help="copy the consultant templates")
    templates.add_argument("--out", required=True)
    templates.set_defaults(run=cmd_templates)
