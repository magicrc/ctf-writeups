# https://app.hackthebox.com/challenges/El%2520Teteo
# Tags: pwn
from pwn import *

warnings.filterwarnings('ignore')
context.arch = 'amd64'

IP="127.0.0.1"
PORT=1337

target = remote(IP, PORT)
target.sendafter("$ ", "flag")
flag = target.recvline_contains(b"HTB").strip().decode()
print(f"[\u2714] Flag captured: \033[1;37m{flag}\033[0m")