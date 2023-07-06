# DNS
DNS, which stands for Domain Name System, is a fundamental protocol used to translate human-readable domain names into IP addresses and vice versa. It plays a crucial role in mapping domain names to their corresponding IP addresses, allowing users to access websites and other network resources using easy-to-remember domain names.

* DNS Enumeration: Penetration testers often perform DNS enumeration to gather information about a target domain. This involves identifying the DNS servers, retrieving DNS records (such as A, AAAA, CNAME, MX, NS, and TXT records), and mapping the DNS infrastructure. This information can be valuable for identifying potential attack vectors or misconfigurations.

* DNS Zone Transfer: DNS zone transfer is a mechanism used to replicate DNS records across multiple DNS servers. Penetration testers assess whether DNS servers allow zone transfers to unauthorized systems, as it can potentially expose sensitive DNS information and aid in reconnaissance.

* DNS Cache Poisoning: DNS cache poisoning refers to the unauthorized modification of DNS cache records, leading to the redirection of legitimate traffic to malicious destinations. Penetration testers evaluate DNS servers for susceptibility to cache poisoning attacks and help identify vulnerabilities that may allow unauthorized modification of DNS records.

*  DNS Amplification Attacks: DNS amplification attacks involve exploiting misconfigured DNS servers to generate a large volume of traffic and overwhelm the target system. Penetration testers assess DNS servers for potential vulnerabilities that could be exploited in such attacks, and provide recommendations to mitigate these risks.

* DNS Tunneling: DNS tunneling is a technique used to bypass network security controls by encapsulating non-DNS traffic within DNS packets. Penetration testers assess if DNS servers allow such tunneling, as it can be used for data exfiltration or unauthorized communication.

## Dig
![Pasted image 20230420152910](https://github.com/dbissell6/Shadow_Stone/assets/50979196/fd88c0c8-b737-40ff-a822-f365ea459ae2)

## Zone Transfer
<img width="786" alt="Screen Shot 2022-09-06 at 2 43 56 PM" src="https://github.com/dbissell6/Shadow_Stone/assets/50979196/b8bfd7d4-88d4-43ac-a04d-e957f4032ccc">

## Fuzz 
Check Fuzzing section
