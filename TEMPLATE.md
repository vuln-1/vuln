# <Vendor> <Product> <Version> was discovered to contain a <vulnerability class> vulnerability

## Overview

- Vendor: <vendor>
- Product: <product/model>
- Version: <version or commit>
- Component: <binary / CGI / handler>
- Vulnerability Class: <CWE-xxx class>
- CVSS 3.1 (tentative): <score> `<vector>`
- Firmware/artifact SHA-256: `<hash>`
- Manufacturer: <vendor website>

## Affected version

<exact firmware version(s), image name and SHA-256>

## Vulnerability details

<root cause, function names, offsets, code snippet>

## PoC

```http
<request>
```

```sh
<command>
```

## Evidence and debug output

<terminal transcript, emulator/debug log, or static decompilation excerpt>

## Impact

<what an attacker gains>

## Remediation

<vendor-side fix>

## Additional Information

```markdown
### Vendor
<vendor>

### Product
<product/model>

### Version or Commit
<version or commit>

### Vulnerability Class
<CWE-xxx: class name>

### CVE_candidate_type
New vulnerability | incomplete-fix variant of CVE-XXXX | new affected model/version — candidate new CVE

### Description
<plain-text summary, no markup, maximum 9000 characters>

### Affected_component
<component path>

### Attack_vector
<short request/trigger description>

### Product_version
<product> <version>

### Reference
- <vendor advisory or download page>
- https://github.com/vuln-1/vuln/blob/main/<Vendor>/<Product>_<Version>/report-N.md
```

## CVE candidate type

- `New vulnerability` — no matching CVE for the product/component.
- `incomplete-fix variant of CVE-XXXX` — the same product/handler was fixed
  before, but the current firmware still exposes a reachable path; candidate
  new CVE.
- `new affected model/version` — the same class is public on another
  model/version, but the current model/version is not in that CVE's affected
  list; candidate new CVE or additional affected product.
