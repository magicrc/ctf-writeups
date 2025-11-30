import sys
from pwn import *

def decrypt_key(xored_flag):
    print("[+] Decrypting key...")
    partial_key = "THM{}"
    decrypted_key = ""
    for i in range(0, len(partial_key) - 1):
        decrypted_key += chr(xored_flag[i] ^ ord(partial_key[i]))
    decrypted_key += chr(xored_flag[-1] ^ ord(partial_key[-1]))
    print("[*] Decrypted key: {}".format(decrypted_key))
    return decrypted_key

def decrypt_flag(xored_flag, key):
    print("[+] Decrypting flag...")
    decrypted_flag = ""
    for i in range(0, len(xored_flag)):
        decrypted_flag += chr(xored_flag[i] ^ ord(key[i % len(key)]))
    print(f"[*] Decrypted flag: {decrypted_flag}")
    return decrypted_flag

target = remote(sys.argv[1], int(sys.argv[2]))
xored_flag = target.recvline_contains(b"This XOR encoded text has flag 1: ").decode().strip().split(": ")[1]
print(f"[*] XORed flag: {xored_flag}")
xored_flag_bytes = bytes.fromhex(xored_flag)
decrypted_key = decrypt_key(xored_flag_bytes)
decrypted_flag = decrypt_flag(xored_flag_bytes, decrypted_key)
print("[+] Sending decrypted key...")
target.sendline(decrypted_key.encode())
second_flag = target.recvline().decode().strip().split(": ")[1]
print(f"[*] Second flag: {second_flag}")
