# Windows

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


