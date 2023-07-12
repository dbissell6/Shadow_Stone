# Kerberos
Kerberos is a network authentication protocol designed to provide secure authentication for client-server applications in a distributed computing environment. It is commonly used in enterprise environments to authenticate users and secure network communications.

* Kerberos Service Enumeration: Penetration testers identify Kerberos-enabled services within the target environment and analyze their configurations. This helps in understanding potential attack surfaces and identifying misconfigurations or vulnerabilities that may exist in the services leveraging Kerberos for authentication.

* Kerberos Authentication: Kerberos employs a ticket-based authentication system, where clients obtain tickets from the Kerberos Key Distribution Center (KDC) to authenticate themselves to network services. Penetration testers assess the strength of Kerberos authentication mechanisms and investigate potential weaknesses or misconfigurations that could lead to unauthorized access.

* Kerberos Ticket Spoofing: Penetration testers evaluate the security of Kerberos tickets, focusing on potential vulnerabilities that may allow ticket manipulation or spoofing. This includes testing for weak encryption algorithms, expired or improperly validated tickets, and other weaknesses that could be exploited by attackers.

* Kerberos Replay Attacks: Penetration testers assess the resistance of Kerberos implementations to replay attacks. They investigate if it is possible to intercept and replay Kerberos tickets to gain unauthorized access to network resources.

* Kerberos Trust Relationships: Kerberos utilizes trust relationships between realms to facilitate authentication across different domains or realms. Penetration testers analyze the trust relationships in place, including cross-realm authentication and trust configurations, to identify potential security weaknesses or misconfigurations that could lead to unauthorized access or privilege escalation.

## Kerbrute
Enumerate users
![Pasted image 20220805223245](https://github.com/dbissell6/Shadow_Stone/assets/50979196/7f96a3d6-f76a-47b5-8f80-51d4ba3b50e5)


```
./kerbrute_linux_amd64 userenum -d sequel.htb --dc 10.129.24.178 /usr/share/wordlists/seclists/Usernames/john.smith.txt -o valid_ad_users

```
## Kerberoast on host
Rubeus

![Pasted image 20230503093118](https://github.com/dbissell6/Shadow_Stone/assets/50979196/2f77773f-05d7-48c9-b0b1-a482d4f15f1f)


The `AS-REProasting` attack is similar to the `Kerberoasting` attack; we can obtain crackable hashes for user accounts that have the property `Do not require Kerberos preauthentication` enabled

![Pasted image 20230503112703](https://github.com/dbissell6/Shadow_Stone/assets/50979196/0abc139c-6a88-4dff-b55d-a663abbb3ef5)
