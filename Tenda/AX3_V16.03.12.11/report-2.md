# Tenda AX3 V16.03.12.11 was discovered to contain a stack buffer overflow in the login password handler

## Overview

- Vendor: Tenda
- Product: AX3 (V16.03.12.11_cn_TDC01)
- Version: V16.03.12.11
- Component: bin/httpd, R7WebsSecurityHandler login path
- Vulnerability Class: CWE-121 stack buffer overflow
- CVSS 3.1 (tentative): 6.5 Medium `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` (valid admin password required; pre-auth reachability not established)
- Manufacturer: https://www.tendacn.com/

## Affected version

- `US_AX3V2.0br_V16.03.12.11_cn_TDC01.bin`.
- UBI `img-1572024763_vol-rootfs_ubifs.ubifs`.
- `bin/httpd`.

## Vulnerability details

`R7WebsSecurityHandler` (0x279ac) handles `/login/Auth`. It declares:

```c
char pcookie[128];   // [sp+0x60] [bp-0x380]
...
Var = websGetVar(wp, "password", "");
v27 = websGetVar(wp, "username", "");
if (strcmp(v27, g_User) || strcmp(Var, g_Pass))
    /* failure path */
...
strcpy(pcookie, Var);   // 0x28450
```

The `strcpy` has no destination-size check. `websGetVar` returns the
request value without a length limit, and `pcookie` is only 128 bytes.
The copy occurs only after the supplied username/password match
`g_User`/`g_Pass`, so it requires valid admin credentials (or a configured
password longer than the destination). It is not an unauthenticated
primitive.

The overflow can overwrite the adjacent `urlbuf[256]`,
`http_true_passwd[256]`, `pagetmp[256]`, `file_path[516]` and eventually
the saved registers/return address on the stack. A long password is
expected to crash httpd; with a configured password longer than 128
bytes, the copy itself is already out of bounds.

## PoC

```http
POST /login/Auth HTTP/1.1
Host: <router>
Content-Type: application/x-www-form-urlencoded

username=<valid-admin>&password=AAAAAAAA... (more than 128 bytes)
```

The password must equal `g_Pass` for the copy to be reached. A router
whose admin password is longer than 128 bytes, or a caller that knows the
valid password, can trigger the overflow.

## Verification

The vulnerable handler in the stock `bin/httpd, R7WebsSecurityHandler login path` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An authenticated caller can overflow a stack buffer in the web server
and cause a denial of service; controlled input may reach the saved return
address. Because the password must match the configured admin password,
this is not a pre-auth compromise and is rated PR:L. If the admin password
is longer than the destination, the overflow occurs with a legitimate
login.

## Remediation / known-CVE relation

- Replace `strcpy(pcookie, Var)` with a bounded copy and reject passwords
  longer than the cookie buffer.
- Cap `password` and `username` at the HTTP parser/form layer; do not rely
  on the client.
- NVD/OSV queries found no AX3 `R7WebsSecurityHandler` `password`
  overflow; CVE-2026-36778 is a different Tenda O3 `username` issue.
  Candidate 0-day; CVE application in progress.

## Additional Information

```markdown
### Vendor
Tenda

### Product
AX3 (V16.03.12.11_cn_TDC01)

### Version or Commit
V16.03.12.11

### Vulnerability Class
CWE-121 stack buffer overflow

### CVE_status
CVE application in progress

### Description
R7WebsSecurityHandler's /login/Auth path copies the password into a fixed stack buffer without a length check, overflowing the stack.

### Affected_component
bin/httpd, R7WebsSecurityHandler login path

### Attack_vector
Authenticated POST /login/Auth with a long password.

### Product_version
AX3 (V16.03.12.11_cn_TDC01) V16.03.12.11

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/AX3_V16.03.12.11/report-2.md
```
