# Fuzzing

Fuzzing is commonly used for enumeration and discovering hidden files or directories within a target system. It is an effective technique to identify additional entry points or potential vulnerabilities.

* Subdomain Enumeration: Fuzzing can be used to discover subdomains of a target domain by trying different combinations or variations of subdomain names.

* Directory Enumeration: Fuzzing directories involves brute-forcing different directory paths or names within a web application or file system. It helps in identifying hidden or undisclosed directories that may contain sensitive information or reveal potential vulnerabilities.

* File Enumeration: Fuzzing files entails trying various file names or extensions to discover files that may not be publicly linked or referenced. This can lead to the identification of hidden files containing sensitive data or configuration information.

* Endpoint Enumeration: Fuzzing can be used to enumerate API endpoints or other service endpoints by testing different paths or parameter values. This helps in identifying undocumented or hidden functionalities that may have security implications.


Tools like Gobuster, FFUF, Feroxbuster, and others are commonly used for fuzzing and enumeration purposes. They provide customizable wordlists, parameter fuzzing options, recursive scanning, and other features to aid in the discovery of hidden assets and potential security weaknesses.

## Directories

![Pasted image 20220805174013](https://github.com/dbissell6/Shadow_Stone/assets/50979196/aed7cf18-807f-42a2-9af1-2d582bebae46)

![Pasted image 20220805174028](https://github.com/dbissell6/Shadow_Stone/assets/50979196/1a02832a-6c1f-4bd9-8e47-b4a4d5fa7d8a)


## Files

## DNS-vhost

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

## feroxbuster
![Pasted image 20220805174002](https://github.com/dbissell6/Shadow_Stone/assets/50979196/c660c189-25fe-4a09-9447-0f6c8b722cf4)
