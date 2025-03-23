#!/bin/bash
# https://app.hackthebox.com/challenges/alphascii%2520clashing
# Tags: MD5 collision

TARGET="127.0.0.1 1337"
SLEEP=0.1
FLAG=$(
(
    sleep $SLEEP
    echo '{"option":"register"}'
    sleep $SLEEP
    echo '{"username":"TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak","password":"pass"}'
    sleep $SLEEP
    echo '{"option":"login"}'
    sleep $SLEEP
    echo '{"username":"TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak","password":"pass"}'
    sleep $SLEEP
) | telnet $TARGET 2> /dev/null | grep -oP 'HTB\{.*?\}')

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"