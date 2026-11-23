# Moxa TN-5916 v3.2/v3.3 was discovered to contain a stack buffer overflow in the web pingTemp handler

## Overview

- Vendor: Moxa
- Product: TN-5900-series / TN-5916 industrial security router
- Version: v3.2 and v3.3
- Component: magicP/WebServer/webs, /goform/net_WebPingGetValue
- Vulnerability Class: CWE-121 stack buffer overflow
- CVSS 3.1 (tentative): 8.8 High `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (9.8 if `/goform/net_WebPingGetValue` is reachable without a session)
- Manufacturer: https://www.moxa.com/

## Affected versions

### v3.2 (2021-12)

- `moxa-tn-5900-series-firmware-v3.2.rom`.
- Extracted big-endian CramFS.
- `magicP/WebServer/webs`.
- `magicP/WebServer/web/ping.asp`.

### v3.3 (2022-10) — still affected

- `moxa-tn-5900-series-firmware-v3.3.rom`.
- Extracted big-endian CramFS.
- `magicP/WebServer/webs`.
- `magicP/WebServer/web/ping.asp`.

## Vulnerability details

`ping.asp` submits a hidden `pingTemp` field to:

```text
/goform/net_WebPingGetValue
```

In v3.2, the `webs` handler table maps this name to
`net_WebPingGetValue` at `0x12002cc74`; that handler starts
`MagicPingThread` at `0x12002c7e0` with a 0x8000-byte thread stack.

In v3.3 the same handler table entry at `0x120174770` maps
`net_WebPingGetValue` to `0x12002d34c`; it starts `MagicPingThread` at
`0x12002ceb8` with the same 0x8000-byte thread stack. The decompiled v3.3
function still contains `char v5[128]`, `websGetVar(..., "pingTemp", "")`,
and the unbounded `strcpy(v5, v1)` before `string_split()` and
`is_ipstring_valid()`.

`MagicPingThread` contains:

```c
char v5[128];
...
Var = websGetVar(ping_wp, "pingTemp", "");
strcpy(v5, Var);
if (!v5[0])
    return 0;
```

`websGetVar` returns the submitted value without truncation. The
unbounded `strcpy` into `v5[128]` occurs **before** `string_split()` and
`is_ipstring_valid()`, so input validation is not a mitigation. The stack
frame continues with `v6[128]`, `v7[8]`, `v8`, `v9[128]`, `v10[138]`, and
`v11`; a sufficiently long `pingTemp` overwrites them and can reach the
saved return address.

The HTML `ping.asp` page limits the `ip` input to 50 characters, but
`pingTemp` is a hidden value and the server does not enforce that limit.

## PoC

```http
POST /goform/net_WebPingGetValue HTTP/1.1
Host: <switch>
Content-Type: application/x-www-form-urlencoded
Cookie: <valid web session if required>

pingTemp=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...&ifs=1&ip=1.2.3.4
```

The oversized `pingTemp` reaches `strcpy(v5, Var)`. A benign long value is
expected to crash the ping thread/web server; controlled data may reach the
saved return address.

## Evidence

Static IDA decompilation of `net_WebPingGetValue` and `MagicPingThread`,
handler-table mapping, the shipped `ping.asp` form, and hashes are under
the parent project:

`experiments/vulnerability-triage/results/20261107-moxa-tn5916-pingtemp-bof-01/evidence/`

(`static-magicping-handler.txt`, `static-ping-strings-xrefs.txt`,
`static-handler-table.txt`, `vendor-ping.asp`, `hashes.txt`).

The v3.3 confirmation is in a separate run:
`experiments/vulnerability-triage/results/20261108-moxa-v33-pingtemp-bof-01/`
(`static-moxa33-ping-decompile.txt`,
`static-moxa33-magicping-disasm.txt`,
`static-moxa33-handler-disasm.txt`, `handler-pointer.txt`,
`vendor-ping-v33.asp`, `hashes.txt`). The handler table at
`0x120174770` contains `0x12002d34c`; the thread function at
`0x12002ceb8` copies `pingTemp` into the 128-byte stack buffer.

Dynamic qemu-mips64 validation was blocked: the extracted MIPS64 rootfs
loader did not start under `qemu-mips64-static` 6.2 (even `busybox`/the
loader exited without output after replacing the CramFS text symlink with
a real `ld.so.1` symlink). The finding is therefore static.

## Impact

A crafted `pingTemp` POST overflows the ping thread's stack. A long value
can crash the web server (DoS); because the overwritten frame includes the
saved return address, controlled data may lead to code execution in the
web-server context. The page is normally accessed after login, so the
primitive is conservatively treated as authenticated LAN operator access;
if the goform route is exposed without a session, it is pre-auth.

## Remediation / known-CVE relation

- Replace `strcpy(v5, Var)` with a bounded copy and reject values longer
  than the destination before any processing.
- Enforce a server-side maximum form-field length; do not rely on HTML
  `maxlength`.
- Move IP validation before all copies and use argv-based execution
  instead of a composed `popen` shell string.
- NVD keyword queries for `Moxa TN-5916`, `Moxa pingTemp`, `Moxa webs
  ping`, and `Moxa MagicPing` returned zero on 2026-11-07.
- CVE-2021-46560 is a TN-5900-through-3.1 command-injection issue; this
  v3.2/v3.3 `pingTemp` stack overflow is a distinct memory-safety issue.
  The v3.3 build still contains the same unbounded copy, so the fix was
  not carried forward. Candidate 0-day; no CVE assigned and no vendor
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
ping.asp submits a hidden pingTemp field; MagicPingThread strcpy's it into a 128-byte stack buffer before string_split and is_ipstring_valid, so a long value reaches the saved return address.

### Affected_component
magicP/WebServer/webs, /goform/net_WebPingGetValue

### Attack_vector
Authenticated POST to /goform/net_WebPingGetValue with an oversized pingTemp value.

### Product_version
TN-5900-series / TN-5916 industrial security router v3.2 and v3.3

### Reference
- https://www.moxa.com/
- https://github.com/vuln-1/vuln/blob/main/Moxa/TN-5916_V3.2/report-5.md
```
