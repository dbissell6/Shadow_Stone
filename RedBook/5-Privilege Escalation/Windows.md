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

