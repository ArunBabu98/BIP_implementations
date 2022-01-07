import hashlib
import binascii
from typing import final
import unicodedata
import os
import secrets 

ent = os.urandom(256//8)
ent_hex = binascii.hexlify(ent)
decoded = ent_hex.decode("utf-8")
ent_bin = binascii.unhexlify(decoded) #random in bin
ent_hex = binascii.hexlify(ent_bin) #random in hex

ent_sha = hashlib.sha256(ent_bin).hexdigest()
checksum = int(256/32)

bin_result = (
    bin(int(decoded, 16))[2:].zfill(bytes * 8)
    + bin(int(ent_sha, 16))[2:].zfill(256)[: bytes * 8 // 32]
)

index_list = []
with open("wordlist.txt", "r", encoding="utf-8") as f:
    for w in f.readlines():
        index_list.append(w.strip())

wordlist = []
for i in range(len(bin_result) // 11):
    #print(bin_result[i*11 : (i+1)*11])
    index = int(bin_result[i*11 : (i+1)*11], 2)
    #print(str(index))
    wordlist.append(index_list[index])

phrase = " ".join(wordlist)
print(phrase)