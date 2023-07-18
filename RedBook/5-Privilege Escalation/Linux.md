# Linux

## General Ideas

## Common Attack Paths

www -> config file in web root leaks users password -> 


## Upgrade Shell
Upgrading from a basic shell is import as some critical abilties (sudo -l) are not possible without it.
```
python3 -c 'import pty;pty.spawn("bash")'
```

```
script /dev/null -c bash
^Z
stty raw -echo; fg
```

![Pasted image 20230118102638](https://github.com/dbissell6/Shadow_Stone/assets/50979196/3cdb7ac8-2b9a-4e97-8756-8186f111ed1a)

## sudo -l
Check which commands user can run as root

<img width="363" alt="Pasted image 20220805224254" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/94cf4baa-8b2b-4165-8ea5-ebdca741320b">

## Enumerate system

### Check OS and Version
```
cat /etc/os-release
```

### Kernal version
```
uname -ar
```
instead of netstat can use
```
ss -tunap
```
instead of ifconfig can use
```
ip addr show
```

### Current users PATH
PATH is an environment variable that specifies the set of directories where an executable can be located. An account's PATH variable is a set of absolute paths, allowing a user to type a command without specifying the absolute path to the binary. 

Adding . to a user's PATH adds their current working directory to the list. For example, if we can modify a user's path, we could replace a common binary such as ls with a malicious script such as a reverse shell. If we add . to the path by issuing the command PATH=.:$PATH and then export PATH, we will be able to run binaries located in our current working directory by just typing the name of the file

```
echo $PATH
```
### Curent users environment variables

```
history
```
## Cred hunt



### All hidden Files

```
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
```
### All hidden Directories
```
find / -type d -name ".*" -ls 2>/dev/null
```
### Files with special permissions
```
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
```

Config files
```
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done
```
Creds in configs
```
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```
Databases
```
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done
```
Notes
```
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```
Scripts
```
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

## Groups

###
```
id
```

### List groups 
```
cat /etc/group
```

### List users of a group
```
getent group sudo
```

### Set-Group-ID (setgid) permission
```
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```
```
find / -perm -u=s -type f 2>/dev/null
```
```
find / -type f -perm -4000 2>/dev/null
```


## Process Search

`ps -aux`
```
pstree
```
### proc
```
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"
```
### pspy

![Pasted image 20220805171804](https://github.com/dbissell6/Shadow_Stone/assets/50979196/9638108c-31f4-4ed4-a0c1-e66e175ce77c)


## Capabilities

Linux capabilities are a valuable security feature in the Linux operating system, enabling the assignment of specific privileges to processes, thereby allowing them to perform particular actions that would typically be restricted. This fine-grained control over privileges offers improved security compared to the traditional Unix model, where privileges are granted to users and groups.

Despite their benefits, Linux capabilities are not without vulnerabilities. For instance, improperly granting capabilities to processes that lack sufficient sandboxing or isolation can lead to privilege escalation, providing unauthorized access to sensitive information and unauthorized actions.



## Network Search

```
cat /etc/hosts
```
### arp table to see who host has been communicating with
```
arp -a
```
![Pasted image 20230508091856](https://github.com/dbissell6/Shadow_Stone/assets/50979196/c1df3135-2b96-4029-ade8-dd00dd96ccad)


<img width="756" alt="Screen Shot 2022-08-27 at 10 46 47 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/bb5b641e-d558-4f28-ba34-fdb7841cad96">

`1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.129.25.115",$_)) "Port $_ is open!"} 2>$null`


