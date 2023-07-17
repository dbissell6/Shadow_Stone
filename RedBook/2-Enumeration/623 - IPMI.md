# IPMI

Intelligent Platform Management Interface (IPMI) is a standardized hardware-based host management system that enables remote management and monitoring of systems. It operates independently of the host's BIOS, CPU, firmware, and OS, allowing management even when the system is powered off or unresponsive. IPMI serves various purposes, including modifying BIOS settings before OS boot, accessing a powered-down host, and managing a system after failure. It provides monitoring capabilities for temperature, voltage, fans, power supplies, inventory information, and hardware logs. IPMI is supported by numerous vendors and requires components like Baseboard Management Controller (BMC), Intelligent Chassis Management Bus (ICMB), and Communications Interfaces for functionality. 

## Scan

```
sudo nmap -Pn -sU --script ipmi-version -p 623 10.129.202.5
```
![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/3fcb4494-323a-4ffa-a9b7-e1333f186ed9)


## Dump Hashes

![image](https://github.com/dbissell6/Shadow_Stone/assets/50979196/83b73439-a21a-433b-9e35-26e2b1cad724)
