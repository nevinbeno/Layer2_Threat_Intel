# CISA KEV: VIP List of Dangerous CVEs
CISA KEV (Cybersecurity and Infrastructure Security Agency – Known Exploited Vulnerabilities Catalog) is NOT just another vulnerability list.
It’s a high-priority danger list maintained by the U.S. government.

#### Meaning
A vulnerability appears in CISA KEV only if **attackers have already used it** in real attacks
(ransomware, APT groups, mass exploitation, etc.).

So, it’s not theoretical, not “maybe”, not “possible”. It’s confirmed and actively exploited.

#### ⚠️ Why this makes it HIGH PRIORITY
Because if it’s exploited in the wild, then:
- Attackers already have working exploits
- Victims already got hacked
- It can be weaponized easily
- Organizations must patch immediately to avoid real attacks

So CISA says:
“These are the vulnerabilities that attackers are ACTUALLY using right now — fix them FIRST.”
____
### CWEs (Common Weakness Enumeration)
`cwes` in the CISA KEV output are references to Common Weakness Enumeration (CWE) identifiers. They are not CVEs themselves, but they describe the type of software weakness or vulnerability that led to the CVE. Think of them as the “category” or “root cause” of the vulnerability.
Example: 
```json
"cwes":[
    "CWE-20", 
    "CWE-77"
]
```
`CWE-20` — **Improper Input Validation**
- This means the software doesn’t properly check or sanitize inputs. Attackers can exploit this to inject unexpected or malicious data.

`CWE-77` — **Command Injection**
- It indicates the vulnerability that allows attackers to execute arbitrary system commands on the host, because input is directly passed to a command interpreter.