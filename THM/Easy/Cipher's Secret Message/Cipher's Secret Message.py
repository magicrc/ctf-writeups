def dec(ciphertext):
    return "".join(
        chr((ord(c) - (base := ord('A') if c.isupper() else ord('a')) - i) % 26 + base)
        if c.isalpha() else c
        for i, c in enumerate(ciphertext)
    )

cipher_text = "a_up4qr_kaiaf0_bujktaz_qm_su4ux_cpbq_ETZ_rhrudm"
plain_text = dec(cipher_text)
flag = f"THM{{{plain_text}}}"

print(f"[\u2714] Flag captured: \033[1;37m{flag}\033[0m")