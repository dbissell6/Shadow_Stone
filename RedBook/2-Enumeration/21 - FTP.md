# FTP

FTP, which stands for File Transfer Protocol, is a standard network protocol used for transferring files between a client and a server on a computer network. It is one of the oldest and most widely used file transfer protocols on the Internet.

In the context of cybersecurity and penetration testing, FTP is of particular interest due to its potential security vulnerabilities. Penetration testers often focus on FTP as a possible entry point or a means to exploit misconfigurations or weaknesses in the FTP implementation.

Here are a few key points about FTP in relation to cybersecurity and penetration testing:

Authentication and Authorization: FTP uses a username and password for authentication. During penetration testing, testers may attempt to exploit weak or default credentials to gain unauthorized access to FTP servers. They also analyze the authorization mechanisms in place to ensure that users are limited to appropriate file access permissions.

Clear-text Transmission: By default, FTP transfers data and credentials in clear text, making it susceptible to interception and eavesdropping. Penetration testers evaluate if FTP connections can be secured by implementing protocols like FTPS (FTP Secure) or SFTP (SSH File Transfer Protocol) to encrypt the data in transit.

Anonymous Access: Some FTP servers allow anonymous access, which enables users to log in without providing credentials. Penetration testers investigate the level of access granted to anonymous users and assess whether it poses a security risk or allows unauthorized file transfers.

FTP Bounce Attack: FTP servers can be vulnerable to a technique called "FTP bounce attack." This attack leverages the FTP server's proxy functionality to connect to other systems, potentially bypassing firewalls or conducting port scanning. Penetration testers look for misconfigured servers that allow FTP bounce attacks and provide recommendations for mitigating this vulnerability.

File and Directory Enumeration: Penetration testers often aim to enumerate the files and directories available on FTP servers. This helps identify sensitive information, potential vulnerabilities, or misconfigurations that could lead to unauthorized access or data leakage.

## Can be misconfigured for anonymous login

