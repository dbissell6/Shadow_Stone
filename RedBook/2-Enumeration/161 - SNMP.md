# SNMP

SNMP, which stands for Simple Network Management Protocol, is a widely used protocol for managing and monitoring network devices and systems. It provides a standardized framework for network administrators to gather information, monitor performance, and manage network devices such as routers, switches, and servers.

* SNMP Enumeration: Penetration testers perform SNMP enumeration to identify SNMP-enabled devices within the target environment. This involves identifying SNMP agents, querying SNMP Management Information Bases (MIBs), and gathering information about the devices, such as system configurations, network interfaces, and performance metrics.

* SNMP Community Strings: SNMP uses community strings as a basic form of authentication. Penetration testers assess the strength of community strings used by SNMP-enabled devices, looking for default or easily guessable community strings that could lead to unauthorized access or information disclosure.

* SNMP Version and Security: SNMP has multiple versions, including SNMPv1, SNMPv2c, and SNMPv3. Penetration testers assess the version in use and analyze the security features implemented, such as authentication, access control, and encryption. They identify vulnerabilities associated with specific versions or configuration weaknesses that could be exploited by attackers.

* SNMP Trap and Notification Analysis: Penetration testers analyze SNMP trap and notification messages sent by devices to network management systems. This analysis helps identify potential security events, misconfigurations, or vulnerabilities that could be leveraged for further attacks or intrusion detection evasion.

* SNMP Brute-Force Attacks: SNMP community strings can be targeted in brute-force attacks to gain unauthorized access to SNMP-enabled devices. Penetration testers assess the resilience of SNMP implementations against such attacks, including rate limiting, account lockouts, or detection mechanisms that can help prevent or mitigate brute-force attacks.

## snmpwalk


```
snmpwalk -v2c -c public 10.10.11.107
```
![Pasted image 20230123074633](https://github.com/dbissell6/Shadow_Stone/assets/50979196/38129adc-c68a-400a-b194-97bc5fb254fa)

## onesixtyone
```
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.11.107
```
