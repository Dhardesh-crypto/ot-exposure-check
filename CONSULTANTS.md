# otcheck for security consultants

Use `otcheck engagement` to review several client sites under one authorisation, record your evidence, produce a client report and show progress at a retest.

The safety rule stays the same: otcheck never connects to client equipment. It reads third-party scan data, files the client gives you and your interview notes. If you're contracted for active testing, use specialist tools for that part and keep it out of this workflow.

**Keep each engagement on encrypted storage, outside any git repository.** Findings describe real weaknesses.

## 1. Get authorisation

Copy the templates, have a lawyer review them, then get the letter signed before starting any work.

```bash
otcheck engagement templates --out my-templates
```

The set covers the authorisation letter, rules of engagement, kick-off and contractor questionnaires, a passive capture guide and an incident hand-off note.

## 2. Set up the engagement

```bash
otcheck engagement --folder client-a new --client "Client A" --consultant "Your name" --authoriser "Their name" --authorisation-ref AUTH-001 --start 2026-11-01 --end 2026-11-30
```

```bash
otcheck engagement --folder client-a add-site --name "North Store" --sector refrigeration --addresses 203.0.113.40 --contractor "Example Cooling Ltd" --control-networks 10.10.0.0/16
```

Commands that collect data refuse to run outside the authorised dates. You can still write reports after the end date. Scan records for addresses outside a site's scope are ignored and counted in the report.

## 3. Collect

Exposure, using `SHODAN_API_KEY` or an export file:

```bash
otcheck engagement --folder client-a exposure --site north-store --import export.json
```

Checklist answers, with who said it and what you saw. The file format is in `fixtures/engagement/north-answers.json`. A `verified` answer needs evidence, and `stated` answers are disclosed in the report.

```bash
otcheck engagement --folder client-a checklist --site north-store --answers answers.json
```

Network logs from Zeek or Malcolm. The client's staff or vendor make the capture. See the passive capture guide.

```bash
otcheck engagement --folder client-a import-traffic --site north-store conn.log
```

An asset list as CSV, with `ip`, `make`, `model` and `firmware` columns, then the support and exploited lists:

```bash
otcheck engagement --folder client-a import-assets --site north-store assets.csv
```

```bash
otcheck engagement --folder client-a match --site north-store --update-kev
```

Results of `match` start with "Check:". A name match doesn't prove a device is vulnerable, so confirm before reporting it as fact.

## 4. Report

```bash
otcheck engagement --folder client-a report
```

This writes three files to `deliverables/`:

- `client-report.html`: summary, cross-site patterns, findings with evidence, and limits
- `findings.csv`: a register for the client's tracker, with owner and due date columns
- `findings.json`: the baseline for a retest

## 5. Retest

Keep the first `findings.json`, collect fresh data, then compare and report again.

```bash
otcheck engagement --folder client-a compare --baseline first-findings.json
```

"No longer found" means the issue is missing from the new data. Confirm each one before calling it fixed.

## 6. Close

Check the activity log, then archive or permanently delete the client's data. Both ask you to type the client name.

```bash
otcheck engagement --folder client-a verify-log
```

```bash
otcheck engagement --folder client-a close archive
```

```bash
otcheck engagement --folder client-a close purge
```

An archive is an unencrypted zip, so move it to encrypted storage. Purge removes the engagement folder from this file system. It can't reach backups or copies, or guarantee secure erasure on every disk. A short closure note with no findings stays beside the folder.

The activity log shows edits to its existing lines, but someone who rewrites the whole file could rebuild it. Treat it as a working record, not as tamper-proof legal evidence.

## If you find a live compromise

Stop and phone the client's contact. Don't wait for the report. Use the incident hand-off template. The operator decides what happens to the plant.

## Status

Early version, tested only on simulated data. The Zeek and Malcolm parser hasn't seen real exports yet, and the support list covers only a few products. It doesn't replace your professional judgement.
