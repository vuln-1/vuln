# Tenda G0-5G-8G-PoEV3.0si V16.01.15.5 was discovered to contain a hardcoded password vulnerability

## Overview
Product: G0-5G-8G-PoEV3.0si

Version: V16.01.15.5

Manufacturer's website information: https://www.tendacn.com/

## Affected version
V16.01.15.5

## Vulnerability description
Tenda G0-5G-8G-PoEV3.0si V16.01.15.5 was discovered to contain a hardcoded password vulnerability in /etc_ro/shadow, which allows attackers to log in as root. By supplying the specific input an attacker can trigger the use of embedded hard-coded credentials. This vulnerability is restricted to local access and demands a sophisticated level of execution, making it relatively challenging to exploit. Nevertheless, the Proof of Concept (PoC) has been released to the public and could be weaponized.

![Shadow Content](./img/shadow_cat.png)

![John Result](./img/john_show.png)

## Additional Information
```markdown
### Vendor
Tenda

### Product
G0-5G-8G-PoEV3.0si

### Version or Commit
V16.01.15.5

### Vulnerability Class
CWE-798 Use of Hard-coded Credentials

### CVE_status
CVE application in progress

### Description
Tenda G0-5G-8G-PoEV3.0si V16.01.15.5 ships a hardcoded root password in /etc_ro/shadow. An attacker who obtains the firmware image can recover the password and log in as root.

### Product_version
G0-5G-8G-PoEV3.0si

V16.01.15.5

### Affected_component
/etc_ro/shadow

### Attack_vector
The root password obtained from /etc_ro/shadow, can be used for unauthorized root login.

### Technical_details
Tenda G0-5G-8G-PoEV3.0si V16.01.15.5 Firmware V16.01.15.5 was discovered to contain a hardcoded password vulnerability in /etc_ro/shadow, which allows attackers to log in as root

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/G0-5G-8G-PoEV3.0si_V16.01.15.5/report-1.md

```
