# Passive capture guide

For agreeing a capture with the client's operator. The client's staff or vendor make the capture.

## Agree first
- The operator and vendor approve the method, location and time.
- Changing a switch configuration is a change to the plant network, so use the client's change process.
- Agree how to back out, and who is on site.

## Safer options
- Use an existing mirror (SPAN) port, or a passive network tap fitted during planned downtime.
- The capture device only listens. It has no address on the control network.
- Don't run active scanners or discovery tools on the control network.

## Capture
- Capture across a normal working period, including shift changes and scheduled maintenance if possible.
- Note the capture point, because logs only show traffic that passes it.
- Treat the capture as confidential. It can include passwords sent unencrypted.

## Prepare for otcheck
Process the capture with Zeek or Malcolm on an isolated machine, then give otcheck the connection logs:

```bash
otcheck engagement import-traffic --site example-site conn.log
```

Delete the raw capture according to the agreed retention period.
