# Intelbras VIP G4/G5 V2.1.4.500306 was discovered to contain an unauthenticated administrator password reset in PasswdFind

## Overview

- Vendor: Intelbras
- Product: VIP 1130 B / 1220 D / 1230 D G4 and G5
- Version: V2.1.4.500306
- Component: sonia /OutsideCmd -> PasswdFind
- Vulnerability Class: CWE-306 missing authentication / CWE-640 weak password recovery
- Manufacturer: https://www.intelbras.com/

## Affected version

- G4 package (1220 D G4 and 1230 D G4).
- G4 `sonia`.
- G5 `sonia`.

## Vulnerability details

`sonia`'s `checkOutSideCmd` pre-login allow-list includes
`PasswdFind.getDescript`, `sendVerificationCode`, `checkAuthCode`,
`resetPassword` (G4 also `setContact`). `setContact` only needs the device
public key to change the recovery contact. The 8-character verification code
is derived as `base64(hex(md5(UTC time + rand()%1000 + contact)))[:8]`; only
1000 nonces exist. `checkAuthCode` and `resetPassword` have no attempt
counter or expiry check. This forms a pre-auth admin password reset chain.

## PoC

```text
# Conceptual request sequence (see parent project for the JSON/protobuf
# wrapper used by the /OutsideCmd RPC):
# 1. PasswdFind.setContact  -> set attacker-controlled recovery contact
# 2. PasswdFind.sendVerificationCode -> derive/guess the 8-char code
# 3. PasswdFind.checkAuthCode
# 4. PasswdFind.resetPassword -> set a new admin password
```

## Reproduction and terminal evidence

No end-to-end dynamic run: the G4/G5 `sonia` binary reaches the vendor PDI
hardware abstraction and crashes under qemu-arm rehost before HTTP is served.
Static evidence is the complete request/response chain and the code-level
derivation above. A real device or a fuller PDI rehost is needed to capture
the terminal transcript.

## Static evidence

The pre-login allow-list, `setContact`/`resetPassword` handlers, and the
`md5(time + rand()%1000 + contact)` derivation are decompiled in
`evidence/ida-PasswdFind.txt` and `evidence/ida-checkOutSideCmd.txt` (parent
project). G4 and G5 `sonia` are byte-identical for this chain.

## Impact

Unauthenticated attacker who can reach the management interface can reset the
admin password and take over the device. G5 builds from 2026-07 still contain
the same derivation chain.

## Remediation

- Require authentication or a physical reset for `setContact` and
  `resetPassword`.
- Use a cryptographically random, single-use, expiring recovery code; rate
  limit attempts.
- Do not derive recovery secrets from time + `rand()` + contact data.

## Known CVE relation

- CVE-2026-36438 covers VIP-1230-D-G4 information disclosure (CWE-640),
  not this reset chain. CVE-2025-67070 is a different 9032 R build/MFA
  bypass. NVD has no exact match; candidate 0-day pending real-device
  confirmation.

## Status and disclosure

Static confirmation; dynamic rehost blocked by vendor PDI hardware
dependencies. Candidate; no CVE assigned. No vendor/CNA contact. Marked
static in the summary table.

## Additional Information

```markdown
### Vendor
Intelbras

### Product
VIP 1130 B / 1220 D / 1230 D G4 and G5

### Version or Commit
V2.1.4.500306

### Vulnerability Class
CWE-306 missing authentication / CWE-640 weak password recovery

### Description
The sonia pre-login allow-list includes PasswdFind methods. An attacker can call setContact to change the recovery contact, request a verification code, and reset the admin password without authentication; the 8-character code is derived from time, rand()%1000 and the contact value, with no expiry check.

### Affected_component
sonia /OutsideCmd -> PasswdFind

### Attack_vector
Unauthenticated /OutsideCmd PasswdFind calls (setContact, getDescript, sendVerificationCode, checkAuthCode, resetPassword).

### Product_version
VIP 1130 B / 1220 D / 1230 D G4 and G5 V2.1.4.500306

### Reference
- https://www.intelbras.com/
- https://github.com/vuln-1/vuln/blob/main/Intelbras/VIP_1220_G4_V2.1.4.500306/report-1.md
```
