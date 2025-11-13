nmap -sn 192.168.1.0/24
nmap -sS -p- 192.168.1.0/24
sudo nmap -sU -p 53,67,68,123 192.168.1.0/24
nmap -sV -sC -p 1-65535 192.168.1.0/24
sudo nmap -A -T4 192.168.1.0/24
nmap -O 192.168.1.100
nmap --script vuln 192.168.1.100
nmap -Pn -p 80,443 -sV example.com
nmap --top-ports 1000 -T4 10.0.0.0/8
nmap -oA scan-results 192.168.1.0/24
