# MW5GV1.0re was discovered to contain a hardcoded password vulnerability

## Overview
Product: MW5GV1.0re

Version: V1.0.0.35

Manufacturer's website information: https://www.tendacn.com/

## Affected version
V1.0.0.35

## Vulnerability description
Tenda MW5GV1.0re V1.0.0.35 was discovered to contain a hardcoded password vulnerability in /etc_ro/shadow, which allows attackers to log in as root. By supplying the specific input an attacker can trigger the use of embedded hard-coded credentials. This vulnerability is restricted to local access and demands a sophisticated level of execution, making it relatively challenging to exploit. Nevertheless, the Proof of Concept (PoC) has been released to the public and could be weaponized.

![Shadow Content](./img/shadow_cat.png)

![John Result](./img/john_show.png)

## Additional Information
```markdown
### Product_version
MW5GV1.0re

V1.0.0.35

### Affected_component
/etc_ro/shadow

### Attack_vector
The root password obtained from /etc_ro/shadow, can be used for unauthorized root login.

### Discription
Tenda MW5GV1.0re V1.0.0.35 Firmware V1.0.0.35 was discovered to contain a hardcoded password vulnerability in /etc_ro/shadow, which allows attackers to log in as root

### Reference
- https://www.tendacn.com/
- https://github.com/vuln-1/vuln/blob/main/Tenda/MW5GV1.0re_V1.0.0.35/report-1.md


```

