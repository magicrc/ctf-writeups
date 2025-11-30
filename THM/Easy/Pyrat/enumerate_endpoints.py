import sys
from pwn import *

def check_endpoint(endpoint) -> str | None:
    target.sendline(endpoint.encode())
    output = target.recvline().decode().strip()
    if output != "" and \
            not output.startswith("invalid syntax") and \
            not output.endswith("is not defined") and \
            not output.startswith("leading zeros in decimal integer literals are not permitted") and \
            not output.startswith("bad operand") and \
            not output.startswith("unsupported operand type"):
        return output
    return None

target = remote(sys.argv[1], int(sys.argv[2]))
print("[+] Enumerating endpoints...")
with open(sys.argv[3], "r") as file:
    for line in file:
        output = check_endpoint(line)
        if output is not None:
            print(f"[*] {line.strip()} -> {output}")
