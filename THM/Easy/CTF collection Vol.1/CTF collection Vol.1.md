| Category          | Details                                                              |
|-------------------|----------------------------------------------------------------------|
| 📝 **Name**       | [CTF collection Vol.1](https://tryhackme.com/room/ctfcollectionvol1) |  
| 🏷 **Type**       | THM Challenge                                                        |
| 🖥 **OS**         | Linux                                                                |
| 🎯 **Difficulty** | Easy                                                                 |

# Solution

#### Capture 1st flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ echo VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ== | base64 -d 
THM{********************}
```

#### Capture 2nd flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ exiftool Find_me_1577975566801.jpg | grep -oP 'THM\{.*?\}'
THM{************}
```

#### Capture 3rd flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ stegseek Extinction_1577976250757.jpg -xf flag.txt && cat flag.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "Final_message.txt".
[i] Extracting to "flag.txt".

It going to be over soon. Sleep my child.

THM{******************************}
```

#### Capture 4th flag
Flag is displayed in challenge web page, with white font on white background.
```
Huh, where is the flag? THM{**********}
```

#### Capture 5th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ zbarimg QR_1577976698747.png 
QR-Code:THM{*****************}
scanned 1 barcode symbols from 1 images in 0.01 seconds
```

#### Capture 6th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ strings hello_1577977122465.hello | grep THM
THM{345y_f1nd_345y_60}
```

#### Capture 7th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ echo 3agrSy1CewF9v8ukcSkPSYm3oKUoByUpKG4L | base58 -d     
THM{17_h45_l3553r_l3773r5}
```

#### Capture 8th flag
```
┌──(magicrc㉿perun)-[~/attack/THM Dav]
└─$ echo "MAF{atbe_max_vtxltk}" | tr 'A-Za-z' 'H-ZA-Gh-za-g'
THM{***************}
```

#### Capture 9th flag
Flag is hidden in HTML `<p>` with `style="display:none;"`
```
<p style="display:none;"> <span data-testid="glossary-term" class="glossary-term">THM</span>{************************}</p>
```

#### Capture 10th flag
Check .png file magic numbers.
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ hexdump -n 16 -C spoil_1577979329740.png
00000000  23 33 44 5f 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |#3D_........IHDR|
00000010
```

Fix .png magic numbers
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ printf '\x89\x50\x4E\x47' | dd of=spoil_1577979329740.png bs=1 seek=0 count=4 conv=notrunc
4+0 records in
4+0 records out
4 bytes copied, 7.0515e-05 s, 56.7 kB/s
```

Read flag by displaying fixed .png `THM{**********}`.

#### Capture 11th flag
1. Check creator of the room - DesKel
2. Use Google query https://www.google.com/search?q=DesKel+reddit+tryhackme
3. `New room Coming soon!` in `/r/tryhackme/` should be on the 1st page
4. Read flag in the post `THM{*******************************}`

#### Capture 12th flag
Use `brainfuck` decoder (e.g. https://md5decrypt.net/en/Brainfuck-translator/) to read the flag, `THM{**********}`.

#### Capture 13th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ python3 -c 'h1=bytes.fromhex("44585d6b2368737c65252166234f20626d"); h2=bytes.fromhex("1010101010101010101010101010101010"); x=bytes(a^b for a,b in zip(h1,h2)); print(f"HEX:{x.hex()}\nASCII:{x.decode()}")'
HEX:54484d7b3378636c75353176335f30727d
ASCII:THM{************}
```

#### Capture 14th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ binwalk hell_1578018688127.jpg                                                         

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.02
30            0x1E            TIFF image data, big-endian, offset of first image directory: 8
265845        0x40E75         Zip archive data, at least v2.0 to extract, uncompressed size: 69, name: hello_there.txt
266099        0x40F73         End of Zip archive, footer length: 22

┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ binwalk -e hell_1578018688127.jpg && cat _hell_1578018688127.jpg.extracted/hello_there.txt

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
265845        0x40E75         Zip archive data, at least v2.0 to extract, uncompressed size: 69, name: hello_there.txt

WARNING: One or more files failed to extract: either no utility was found or it's unimplemented

Thank you for extracting me, you are the best!

THM{***************}
```

#### Capture 15th flag
Use `Blue plane 1` of https://github.com/Giotino/stegsolve to read the flag. 
```
THM{*****************************}
```

#### Capture 16th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ zbarimg QRCTF_1579095601577.png 
QR-Code:https://soundcloud.com/user-86667759/thm-ctf-vol1
scanned 1 barcode symbols from 1 images in 0 seconds
```
Follow URL and 'listen' to flag, `THM{**********}`.

#### Capture 17th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ curl -s http://web.archive.org/web/20200102131252/https://www.embeddedhacker.com/ | grep -oP 'THM{.*}'
THM{******************}
```

#### Capture 18th flag
Crack key using provided plain text.
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ python3 - << 'EOF'
cipher = "MYKAHODTQ"
plain  = "TRYHACKME"
key = ""
for c, p in zip(cipher, plain):
    kc = (ord(c) - ord(p)) % 26
    key += chr(kc + ord('A'))
print(f"Repated key: {key}")
EOF
Repated key: THMTHMTHM
```

Decipher cipher text using discovered key.
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ python3 - << 'EOF'                                 
def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    key = key.upper()
    plaintext = ""

    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            # A=0..Z=25
            c_val = ord(c) - ord('A')
            k_val = ord(key[key_index % len(key)]) - ord('A')
            p_val = (c_val - k_val) % 26
            plaintext += chr(p_val + ord('A'))
            key_index += 1
        else:
            plaintext += c
    return plaintext

ciphertext = "MYKAHODTQ{RVG_YVGGK_FAL_WXF}"
key = "THM"
plain = vigenere_decrypt(ciphertext, key)
print("Plaintext:", plain)
EOF
Plaintext: TRYHACKME{*****************}
```

#### Capture 19th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ python3 - << 'EOF'
n = 581695969015253365094191591547859387620042736036246486373595515576333693
h = hex(n)[2:]
print(bytes.fromhex(h).decode(errors="ignore"))
EOF
THM{*************************}
```

#### Capture 20th flag
```
┌──(magicrc㉿perun)-[~/attack/THM CTF collection Vol.1]
└─$ tshark -r flag_1578026731881.pcapng -V | grep THM 
    THM{***************}\n
```
