## Enumerating Windows Systems

Windows systems present unique challenges and opportunities for penetration testers due to their use of Active Directory and multiple authentication protocols. In this section, we will explore essential tools and methodologies tailored for enumerating Windows operating systems

A typical easy attack path for linux machine might be, abuse web vuln to get shell, abuse service to get root. An easy windows attack path may look like 1) leak usernames from ldap 2) find company password from anonoymous login smb share 3) password spray 4) login to smb...
The early enumeration phase is typically done without creds, then redone with the credentialed user.

## responder

Purpose: Responder is a network security tool used for collecting and abusing network protocols to capture sensitive information, such as usernames and passwords, during Windows network assessments.

Significance: It takes advantage of common network vulnerabilities, such as LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service), to intercept and capture network authentication requests, allowing penetration testers to obtain credentials or gain access to systems.

How it works: Responder passively listens for network traffic and responds to specific types of requests. When a victim system sends a request for a resource, Responder intercepts and responds with a malicious response, tricking the system into sending its authentication credentials.

Typically in HTB machines need a bot to interact with you to trigger it. It is also used when getting a MSSQL session to leak creds.

![Pasted image 20230508072805](https://github.com/dbissell6/Shadow_Stone/assets/50979196/8b799af5-7e29-4bc6-a8a3-f7083b030e53)

![Pasted image 20230508072838](https://github.com/dbissell6/Shadow_Stone/assets/50979196/dc75e93c-3cbe-4792-941d-2cfcce3868e1)

Inveigh will perform the same function, typically used on victim machine with elevated privs.

## bloodhound

Purpose: BloodHound is a post-exploitation tool designed to map and visualize Active Directory (AD) environments. It helps identify vulnerabilities and potential attack paths, assisting in privilege escalation and lateral movement.

Significance: BloodHound provides valuable insights into AD permissions, trust relationships, group membership, and user behaviors, helping penetration testers understand the AD structure and locate potential security weaknesses.

How it works: BloodHound utilizes graph theory and data analysis to collect and process information about AD environments. By leveraging the data gathered from various sources, such as Group Policy Objects (GPOs), user accounts, and domain trusts, BloodHound generates a visual graph representation of the AD environment, highlighting potential attack paths and vulnerabilities.


bloodhound with creds
`python3 ~/BloodHound.py/bloodhound.py -d streamio.htb -u JDGodd -p 'JDg0dd1s@d0p3cr3@t0r' -gc dc.streamio.htb -ns 10.10.11.158 -c all --zip`

Check priv escalation for running bloodhound on the host. 
## impacket
