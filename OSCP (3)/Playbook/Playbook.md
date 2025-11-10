
### Enumeration

1. Enumerate the network
	1. Use MSF to keep track of hosts and services
		1. Save down all enumeration and scans in to -o files
	2. Identify services and versions
		1. Use dorking to identify known vulnerabilities
		2. Use searchsploit to identify known vulnerabilities
		3. FUZZ web pages for directories
		4. Manually go through the web application and check source code
		5. Use Automatic tools
			1. whatweb
			2. nikto
			3. wpscan
	3. Re-iterate enumeration process for new discoveries such as services and hosts!!
	4. Use the Joplin template to document each target

&nbsp;

### Exploiting the target

1. Enumerate the target:
	1. Linux
		1. Run linpeas
		2. Check network interfaces
		3. Check for SUID
		4. Check for sudo -l
		5. Check for password leaks
		6. Check for .git repos
		7. When elevated privs are gained run linpeas again!
	2. Windows
		1. Run winpeas
		2. Check scheduled tasks 
		3. Search for files in C:\Users\
		4. Check privs
			1. If SeImpersonatePrivilege is set make sure to run multiple exploit tools since some works sometimes and other not
				1. PrintSpoofer
				2. GodPotato
				3. RougePotato

&nbsp;

### Fundamentals
- Always conduct thorough enumeration!
	- Meaning if you find a potential attack path, document it down and keep enumerating!
- When admin privs is obtained on a target, do not jump straight to the next machine!
	- Examine the system for things that may have been previously inaccessible.
- Detailed note keeping is extreemly important
	- Use:
		- msf to keep track of hosts and services db_nmap
		- Create files and directories to keep track of targets, such as:
			- creds.txt
			- usernames.txt
			- passwords.txt
			- computers.txt
- Report:
	- Keep lots of notes on the actual exploit steps taken
	- Take a lot of screenshoots for the report
