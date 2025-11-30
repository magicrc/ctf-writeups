# Target
| Category          | Details                                         |
|-------------------|-------------------------------------------------|
| 📝 **Name**       | [TakeOver](https://tryhackme.com/room/takeover) |  
| 🏷 **Type**       | THM Machine                                     |
| 🖥 **OS**         | Linux                                           |
| 🎯 **Difficulty** | Easy                                            |
| 📁 **Tags**       | Web enumeration                                 |

# Scan
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4a:c2:2f:08:08:93:77:8a:fc:e5:db:2a:0f:b9:45:60 (RSA)
|   256 ba:5e:76:38:bd:7a:d1:1b:88:4d:74:43:20:c0:7a:29 (ECDSA)
|_  256 68:83:2a:1f:1e:a3:91:a7:a2:43:61:aa:09:a2:f2:64 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://futurevera.thm/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
|_http-title: FutureVera
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
| ssl-cert: Subject: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US
| Not valid before: 2022-03-13T10:05:19
|_Not valid after:  2023-03-13T10:05:19
```

#### Add `futurevera.thm` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM TakeOver]
└─$ echo "$TARGET futurevera.thm" | sudo tee -a /etc/hosts
10.82.147.68 futurevera.thm
```

#### Enumerate virtual hosts
```
┌──(magicrc㉿perun)-[~/attack/THM TakeOver]
└─$ gobuster vhost --url https://$TARGET --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -k -ad --domain futurevera.thm        
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       https://10.82.151.234
[+] Method:                    GET
[+] Threads:                   10
[+] Wordlist:                  /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
blog.futurevera.thm Status: 200 [Size: 3838]
support.futurevera.thm Status: 200 [Size: 1522]
```

#### Add `blog.futurevera.thm` and `support.futurevera.thm` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM TakeOver]
└─$ echo "$TARGET blog.futurevera.thm support.futurevera.thm" | sudo tee -a /etc/hosts
10.82.147.68 blog.futurevera.thm support.futurevera.thm
```

#### Discover `secrethelpdesk934752.support.futurevera.thm` in `Subject Alternative Name` for `support.futurevera.thm` certificate
```
┌──(magicrc㉿perun)-[~/attack/THM TakeOver]
└─$ openssl s_client -connect support.futurevera.thm:443 </dev/null 2>/dev/null | openssl x509 -inform pem -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6a:e5:b7:73:1d:02:cd:10:73:a9:88:e0:e4:73:1a:3f:00:88:6c:92
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, ST=Oregon, L=Portland, O=Futurevera, OU=Thm, CN=support.futurevera.thm
        Validity
            Not Before: Mar 13 14:26:24 2022 GMT
            Not After : Mar 12 14:26:24 2024 GMT
        Subject: C=US, ST=Oregon, L=Portland, O=Futurevera, OU=Thm, CN=support.futurevera.thm
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:9a:9b:64:c8:70:9a:13:d1:5e:0e:c8:93:eb:02:
                    da:f7:25:6f:c7:d7:8c:6b:3f:14:90:1d:ed:c9:8f:
                    1a:b0:48:7d:47:71:08:75:dc:d7:49:47:26:65:fe:
                    11:68:36:92:89:40:8b:ab:fb:61:0f:37:7d:92:48:
                    7a:00:23:41:72:ef:1f:9c:27:13:4c:8d:e4:65:e5:
                    30:c5:b1:4e:5a:7f:e4:df:ec:fc:e2:f3:19:c5:d1:
                    cf:36:38:e0:b4:44:33:84:f2:c5:61:3f:63:85:33:
                    1f:79:ad:2d:bc:dc:ac:55:c2:3a:42:18:70:73:90:
                    7b:2f:21:52:c3:8c:8b:e1:b3:76:f4:5d:f9:ec:71:
                    aa:3e:1f:d3:cf:ae:82:52:36:43:01:65:ce:59:44:
                    9e:8c:62:d1:e6:ef:83:0f:75:57:66:6d:6b:b2:21:
                    e3:64:68:af:ac:95:0e:f7:c4:a6:61:47:19:58:95:
                    48:54:2e:1c:f1:ba:bb:22:e2:a8:09:4b:94:a9:0d:
                    07:5c:e1:f5:45:77:75:45:6b:d4:c9:d1:55:01:59:
                    4b:17:ba:98:9b:03:70:c5:4e:69:28:19:2c:83:41:
                    18:c4:c0:17:0e:a1:67:1f:a8:5e:95:58:0f:81:24:
                    bf:df:fc:e2:ab:3f:54:c7:b8:0b:90:bc:21:f0:6b:
                    b6:2b
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: 
                Key Encipherment, Data Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Subject Alternative Name: 
                DNS:secrethelpdesk934752.support.futurevera.thm
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        93:51:84:0b:22:3b:07:6b:8d:82:40:38:24:a8:e8:e6:33:19:
        5b:c3:e6:04:de:50:5f:85:fc:ec:de:40:cb:4c:b5:f4:c5:da:
        b5:f8:9a:8d:c0:c5:54:d7:43:d2:c5:2a:84:1b:9f:2d:a1:95:
        6e:98:73:f5:cb:bd:a7:de:09:57:50:4e:44:12:98:c4:3a:a0:
        df:59:ee:95:ed:09:f3:af:ca:d1:a7:57:1e:a1:f2:f1:de:d5:
        c6:36:0e:d4:18:29:74:c2:d3:2f:d9:24:21:25:f6:1b:18:56:
        3e:fe:75:95:bf:7f:8f:c5:15:1a:1d:80:f2:28:da:91:f7:39:
        21:a4:a6:2d:7d:ca:3d:54:75:47:62:20:1b:a3:85:59:c0:b3:
        4c:ea:4b:b2:c4:a5:ea:0d:23:eb:95:94:3e:96:bc:18:0c:f5:
        45:a0:8c:a0:8c:89:ef:1a:fd:57:aa:b1:c9:6b:1c:cd:65:f9:
        5a:0c:c7:34:fb:00:5c:d1:23:0e:0f:76:07:b9:39:e5:6c:8d:
        21:a8:48:2b:d9:d4:fb:21:c3:50:78:41:ab:50:be:c7:e6:d8:
        60:1b:06:ee:71:1b:97:21:7c:aa:cf:51:d4:a6:b3:41:1d:c4:
        f5:4c:ea:14:94:5e:0e:62:6f:55:9c:7c:ef:01:7f:01:71:fc:
        58:f0:de:72
-----BEGIN CERTIFICATE-----
MIID1DCCArygAwIBAgIUauW3cx0CzRBzqYjg5HMaPwCIbJIwDQYJKoZIhvcNAQEL
BQAwdTELMAkGA1UEBhMCVVMxDzANBgNVBAgMBk9yZWdvbjERMA8GA1UEBwwIUG9y
dGxhbmQxEzARBgNVBAoMCkZ1dHVyZXZlcmExDDAKBgNVBAsMA1RobTEfMB0GA1UE
AwwWc3VwcG9ydC5mdXR1cmV2ZXJhLnRobTAeFw0yMjAzMTMxNDI2MjRaFw0yNDAz
MTIxNDI2MjRaMHUxCzAJBgNVBAYTAlVTMQ8wDQYDVQQIDAZPcmVnb24xETAPBgNV
BAcMCFBvcnRsYW5kMRMwEQYDVQQKDApGdXR1cmV2ZXJhMQwwCgYDVQQLDANUaG0x
HzAdBgNVBAMMFnN1cHBvcnQuZnV0dXJldmVyYS50aG0wggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCam2TIcJoT0V4OyJPrAtr3JW/H14xrPxSQHe3Jjxqw
SH1HcQh13NdJRyZl/hFoNpKJQIur+2EPN32SSHoAI0Fy7x+cJxNMjeRl5TDFsU5a
f+Tf7Pzi8xnF0c82OOC0RDOE8sVhP2OFMx95rS283KxVwjpCGHBzkHsvIVLDjIvh
s3b0Xfnscao+H9PProJSNkMBZc5ZRJ6MYtHm74MPdVdmbWuyIeNkaK+slQ73xKZh
RxlYlUhULhzxursi4qgJS5SpDQdc4fVFd3VFa9TJ0VUBWUsXupibA3DFTmkoGSyD
QRjEwBcOoWcfqF6VWA+BJL/f/OKrP1THuAuQvCHwa7YrAgMBAAGjXDBaMAsGA1Ud
DwQEAwIEMDATBgNVHSUEDDAKBggrBgEFBQcDATA2BgNVHREELzAtgitzZWNyZXRo
ZWxwZGVzazkzNDc1Mi5zdXBwb3J0LmZ1dHVyZXZlcmEudGhtMA0GCSqGSIb3DQEB
CwUAA4IBAQCTUYQLIjsHa42CQDgkqOjmMxlbw+YE3lBfhfzs3kDLTLX0xdq1+JqN
wMVU10PSxSqEG58toZVumHP1y72n3glXUE5EEpjEOqDfWe6V7Qnzr8rRp1ceofLx
3tXGNg7UGCl0wtMv2SQhJfYbGFY+/nWVv3+PxRUaHYDyKNqR9zkhpKYtfco9VHVH
YiAbo4VZwLNM6kuyxKXqDSPrlZQ+lrwYDPVFoIygjInvGv1XqrHJaxzNZflaDMc0
+wBc0SMOD3YHuTnlbI0hqEgr2dT7IcNQeEGrUL7H5thgGwbucRuXIXyqz1HUprNB
HcT1TOoUlF4OYm9VnHzvAX8BcfxY8N5y
-----END CERTIFICATE-----
```

#### Find flag in HTTP server `Location` header 
```
┌──(magicrc㉿perun)-[~/attack/THM TakeOver]
└─$ curl -v http://$TARGET -H "Host: secrethelpdesk934752.support.futurevera.thm" -k
*   Trying 10.82.147.68:80...
* Connected to 10.82.147.68 (10.82.147.68) port 80
* using HTTP/1.x
> GET / HTTP/1.1
> Host: secrethelpdesk934752.support.futurevera.thm
> User-Agent: curl/8.15.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 302 Found
< Date: Wed, 26 Nov 2025 16:09:57 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Location: http://flag{********************************}.s3-website-us-west-3.amazonaws.com/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 10.82.147.68 left intact
```