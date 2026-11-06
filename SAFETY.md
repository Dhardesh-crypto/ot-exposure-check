# Safety rules

Industrial equipment can behave badly when probed, and a mistake can affect food safety, water supply or people. These rules are part of the product.

## What otcheck does

- Reads scan data that a third party has already collected.
- Reads the answers you give it.
- Looks up the registered owner of your addresses in public internet registries.

## What otcheck never does

- Connect to your controllers, control screens or public addresses.
- Scan, probe, exploit or guess passwords.
- Write to or change any device.
- Send your site data anywhere except the lookups above.

Network access is limited to one module, `otcheck/net.py`, which only allows Shodan and the internet registries. `tests/test_safety.py` checks this.

## What these lookups reveal

A live lookup sends your addresses to Shodan and to registry services. Use `otcheck exposure --import` if you would rather not send them from this tool. `otcheck init` always asks the registries who owns each real address, so that you can check you typed them correctly.

## Rules for users

- Only check sites you are authorised to review. The authorisation statement is printed in the report.
- Agree changes with the operator and the vendor first. Disconnecting a link can also disconnect monitoring or alarms.
- If you find signs of tampering, follow your incident plan and contact your vendor and national reporting body.
- Treat reports as confidential.

## Rules for contributors

Do not add active scanning, exploits, credential testing or device writes. Anyone adding a network destination must explain why in the pull request and update `ALLOWED_HOSTS` and this file.
