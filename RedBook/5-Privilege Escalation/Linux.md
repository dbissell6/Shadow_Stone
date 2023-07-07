# Linux

## Upgrade Shell

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
```
history
```
```
pstree
```
```
uname -ar
```
instead of netstat can use
```
ss -tunap
```

## Cred hunt

```
find / -perm -u=s -type f 2>/dev/null
```
```
find / -type f -perm -4000 2>/dev/null
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







