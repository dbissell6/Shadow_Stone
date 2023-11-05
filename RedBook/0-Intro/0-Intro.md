# Introduction to Red Teaming

The attack chain, also known as the cyber kill chain or attack lifecycle, is a systematic process that reflects the stages of a cyberattack from early reconnaissance to achieving the ultimate goal of data exfiltration and maintaining a presence within the target network. Understanding each phase helps red teams to simulate realistic attacks, assess the security posture of an organization, and develop robust defenses.

![Pasted image 20220805171026](https://github.com/dbissell6/Shadow_Stone/assets/50979196/55419ee4-8431-4925-a8c0-3378cc92952e)


1. External Reconnaissance (Recon)

    * Objective: Gather as much information as possible about the target to find vulnerabilities that can be exploited.
    * Activities:
        - OSINT (Open Source Intelligence) techniques.
        - Social engineering to gather intel from employees.
        - Network scanning and enumeration.
        - Identifying exposed services, applications, and valid user accounts.

2. Delivery

    * Objective: Deliver the malicious payload to the target environment.
    * Methods:
        - Spear-phishing emails with malicious attachments or links.
        - Watering hole attacks targeting websites frequently visited by the target audience.
        - Physical means, such as USB drops or other removable media.

3. Exploitation

    * Objective: Exploit a vulnerability to execute the payload and establish a foothold.
    * Techniques:
        - Exploiting known software vulnerabilities (zero-days or unpatched systems).
        - Client-side exploits via compromised websites or malicious ads.
        - Social engineering to trick users into executing the payload.

4. Situational Awareness

    * Objective: Understand and map the environment for further exploitation.
    * Activities:
        - Network discovery to find active machines, roles, and services.
        - Credential dumping and account discovery.
        - Identifying security tools and controls in place (e.g., antivirus, EDR, SIEM).

5. Lateral Movement

    * Objective: Move within the network to gain access to additional systems and increase control.
    * Strategies:
        - Use of stolen credentials to access other systems.
        - Exploiting trust relationships between systems.
        - Pass-the-hash/ticket attacks to authenticate without passwords.

6. Privilege Escalation (PrivEsc)

    * Objective: Gain higher-level permissions on the system or network.
    * Techniques:
        - Exploiting system or application vulnerabilities for higher privileges.
        - Credential access and escalation (e.g., from user to admin).
        - Misconfigurations and system weaknesses.

7. Persistence

    * Objective: Maintain long-term access to the environment for continued exploitation.
    * Methods:
        - Creating backdoors and rootkits.
        - Hijacking legitimate processes or services.
        - Scheduled tasks, registry modifications, or rogue accounts.

8. Data Collection

    * Objective: Identify and gather valuable data from the target network.
    * Actions:
        - Data identification (sensitive files, intellectual property, personal data).
        - Data aggregation and staging for exfiltration.
        - Avoiding detection and maintaining data integrity.

9. Exfiltration

    * Objective: Transfer the collected data from the target network to the attacker’s control.
    * Approaches:
        - Encrypted channels to avoid detection (e.g., HTTPS, DNS tunneling).
        - Splitting and obfuscation of data to bypass DLP measures.
        - Utilizing compromised accounts to access cloud storage services.
