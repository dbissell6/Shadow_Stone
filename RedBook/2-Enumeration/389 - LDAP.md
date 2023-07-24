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
