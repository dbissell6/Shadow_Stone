# Nmap
Nmap, short for "Network Mapper," is a powerful and popular open-source network scanning tool. It is widely used in the field of cybersecurity, particularly in penetration testing and network reconnaissance.  Nmap is designed to provide a comprehensive view of network hosts and services by actively scanning and probing them. It can identify open ports, detect the version of services running on those ports, and gather other valuable information about the target network.

## Popular flags

` -sV ` - Performs service version detection on specified ports.

`-A ` -Perform more aggressive scan than sV

`-sC` - Performs script enumeration.

`-sU` - Performs a UDP scan.

`-Pn` - Disables ICMP Echo requests.

`-F` - Scans top 100 ports.

`--reason` - Displays the reason a port is in a particular state.

`--min-rate 300` - Sets the minimum number of packets to be sent per second.

`-p` - port

`--disable-arp-ping` - disable arp ping

`--packet-trace` - Trace the packets

`-D` - Decoys

## Sample commands
```
nmap -p- --min-rate 10000 10.10.11.153 -Pn -v
```
```
nmap -sC -sV -v -Pn --reason IP
```

```
nmap -p- -v -sC -sV --open --min-rate=1000 10.10.11.142
```


UDP scan

```
sudo nmap 10.129.2.28 -F -sU
```

## Using a script



## IDS/IPS evasion

RND: 5 - 5 random IP to mask

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/ea519f55-1606-4a42-aab4-2c278fa0a154)


## Nmap without nmap
<img width="192" alt="Pasted image 20220807171657" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/2eec3cdf-6795-439f-b68f-62f72a656d0a">
