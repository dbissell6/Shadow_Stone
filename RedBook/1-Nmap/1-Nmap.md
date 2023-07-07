# Nmap
Nmap, short for "Network Mapper," is a powerful and popular open-source network scanning tool. It is widely used in the field of cybersecurity, particularly in penetration testing and network reconnaissance.  Nmap is designed to provide a comprehensive view of network hosts and services by actively scanning and probing them. It can identify open ports, detect the version of services running on those ports, and gather other valuable information about the target network.

## Popular flags

` -sV ` - Performs service version detection on specified ports.

`-sC` - Performs script enumeration.

`-sU` - Performs a UDP scan.

`-Pn` - Disables ICMP Echo requests.

`-F` - Scans top 100 ports.

`--reason` - Displays the reason a port is in a particular state.

`--min-rate 300` - Sets the minimum number of packets to be sent per second.

`-p` - port

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

