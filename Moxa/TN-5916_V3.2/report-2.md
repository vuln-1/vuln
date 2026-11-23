# Moxa TN-5916 v3.2/v3.3 was discovered to contain a stack buffer overflow in the web IP-client configuration handler

## Overview

- Vendor: Moxa
- Product: TN-5900-series / TN-5916 industrial security router
- Version: v3.2 and v3.3
- Component: magicP/WebServer/webs, /goform/net_WebIPCLIENTGetValue
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

`wan.asp` posts WAN/IP-client settings to
`/goform/net_WebIPCLIENTGetValue?wan=1`. The handler copies seven
user-controlled strings into a 300-byte stack `ipclientinfo` structure
with plain `strcpy`, without checking the destination slot or the
server-side length:

```c
_DWORD v31[75];             // 300-byte struct at sp+0x144
...
strcpy((char *)&v31[36] + 3, pptp_user);   // offset 147
strcpy((char *)&v31[45] + 2, pptp_pswd);   // offset 182
strcpy((char *)&v31[10],     poe_user);    // offset 40
strcpy((char *)&v31[18] + 3, poe_pswd);    // offset 75
strcpy((char *)&v31[27] + 3, poe_host);    // offset 111
strcpy((char *)&v31[54] + 2, hostname);    // offset 218
strcpy((char *)&v31[63] + 2, domain);      // offset 254
```

The client-side `maxlength` values (35/47) do not bound the server.
The last field starts at offset 254 of the 300-byte structure, so any
`domain` value longer than 46 bytes already writes past `v31` into
`v32`/`v33`; a value of about 854 bytes reaches the saved `ra` at
`sp+0x598`. `hostname` at offset 218 reaches `ra` after about 890 bytes.

A second issue is the `wan` selector: `v27 = atoi(wan) - 1` and
`memcpy(v31, &v30[75 * v27], 300)` has no bounds check. `wan=0`
selects `v30[-75]` and copies 300 bytes of preceding stack data into
`v31`; large values read further out of bounds. The data is then sent
to the configuration daemon and may influence later parsing.

The v3.3 function allocates 1440 bytes and saves `ra` at `sp+0x598`;
the v3.2 build has the same layout and `strcpy` sequence, and no stack
canary check.

## PoC

```http
POST /goform/net_WebIPCLIENTGetValue?wan=1 HTTP/1.1
Host: <router>
Content-Type: application/x-www-form-urlencoded
Cookie: <authenticated web session>

proto=0&state=1&ipaddr=192.0.2.10&netmask=255.255.255.0&gateway=192.0.2.1&domain=AAAAAAAA... (about 900 bytes) ...AAAA
```

The `domain` value longer than the remaining 46 bytes of `v31` and
about 854 bytes to `ra` overwrites the saved return address; shorter
values corrupt the adjacent `v32`/`v33` locals and can crash the web
server. At minimum this is an authenticated DoS; with a MIPS64 ROP chain
it is a code execution candidate.

## Verification

The vulnerable handler in the stock `magicP/WebServer/webs, /goform/net_WebIPCLIENTGetValue` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An authenticated web user can overflow the management server stack and
potentially execute code in its MIPS64 context. The same request can
also drive the unchecked `wan` index to copy out-of-bounds stack data
into the configuration structure.

## Remediation / known-CVE relation

- Replace every `strcpy` with a bounded copy sized to the actual
  destination slot, and enforce the same limits server-side.
- Bounds-check `wan` against the number of `v30` records before using
  `v27`.
- Add a stack canary and compile `webs` with `-fstack-protector`.
- NVD keyword searches on 2026-11-08 for `net_WebIPCLIENTGetValue`,
  `ipTemp Moxa`, `Moxa TN-5916 buffer overflow` and the field names
  returned zero results. Candidate 0-day; no CVE assigned and no vendor
  contact has been made.

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
wan.asp sends WAN/IP-client settings to /goform/net_WebIPCLIENTGetValue. The handler strcpy's seven user-controlled strings into a 300-byte stack structure without checking slot boundaries.

### Affected_component
magicP/WebServer/webs, /goform/net_WebIPCLIENTGetValue

### Attack_vector
Authenticated POST to /goform/net_WebIPCLIENTGetValue?wan=1 with oversized IP-client fields.

### Product_version
TN-5900-series / TN-5916 industrial security router v3.2 and v3.3

### Reference
- https://www.moxa.com/
- https://github.com/vuln-1/vuln/blob/main/Moxa/TN-5916_V3.2/report-2.md
```
