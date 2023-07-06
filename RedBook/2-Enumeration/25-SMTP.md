# SMTP

SMTP, which stands for Simple Mail Transfer Protocol, is a widely used network protocol for sending and receiving email messages. It is responsible for the transfer of email between mail servers, enabling communication between email clients and mail servers.

* Email Relay and Open Relays: SMTP servers can be misconfigured to allow unauthorized email relaying, leading to abuse by spammers or attackers. Penetration testers assess whether the SMTP server permits relaying and test for open relay vulnerabilities, which can potentially be exploited to send unsolicited emails.

*  Authentication and Authorization: SMTP servers often require authentication before allowing email transmission. Penetration testers examine the authentication mechanisms in place, such as username and password or secure authentication methods like STARTTLS or SSL/TLS, to ensure secure and authorized access.

*  Email Spoofing: SMTP servers that do not properly validate the sender's identity can be vulnerable to email spoofing attacks. Penetration testers assess whether the server implements proper sender authentication mechanisms, such as SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting, and Conformance), to prevent email spoofing and enhance email security.

* Email Header Analysis: Penetration testers often analyze email headers to gather information about the email delivery process, identify potential security issues, or trace the origin of email messages. This analysis can help identify anomalies, detect email tampering attempts, or uncover potential attack vectors.

* Email Filtering and Antispam: SMTP servers can employ filtering mechanisms to detect and block spam, malicious content, or phishing emails. Penetration testers evaluate the effectiveness of these filters and explore ways to bypass them, if applicable, to assess the server's resilience against unwanted or malicious email traffic.

## Enumerate 

<img width="420" alt="Screen Shot 2022-08-07 at 2 02 19 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/c4f18ed0-6aef-4da2-979b-312d322a9d6f"><br>

<img width="436" alt="Screen Shot 2022-08-14 at 4 17 25 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/e2a3d366-c0dd-4156-8c75-6bda6a66c712"><br>
 
<img width="398" alt="Screen Shot 2022-08-07 at 1 50 01 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/b1a3b06a-0b5e-4a0c-a86f-e7239d985b82">

## Send an Email

<img width="799" alt="Screen Shot 2022-08-15 at 6 23 12 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/0a169bd1-943e-469f-95fb-9a04b86190d7">
