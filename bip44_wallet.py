import os
import binascii
import hashlib
import unicodedata

bits = 256
print("Bytes = " + str(bits//8))
ent = os.urandom(bits//8)
ent_hex = binascii.hexlify(ent)
decoded = ent_hex.decode("utf-8")
ent_bin = binascii.unhexlify(str(decoded)) #random in bin
ent_hex = binascii.hexlify(ent_bin) #random in hex
bytes = len(ent_bin)


hashed_sha256 = hashlib.sha256(ent_bin).hexdigest()

result = (
    bin(int(ent_hex, 16))[2:].zfill(bytes * 8)
    + bin(int(hashed_sha256, 16))[2:].zfill(256)[: bytes * 8 // 32]
)


index_list = []
with open("wordlist.txt", "r", encoding="utf-8") as f:
    for w in f.readlines():
        index_list.append(w.strip())

wordlist = []
for i in range(len(result) // 11):
    #print(result[i*11 : (i+1)*11])
    index = int(result[i*11 : (i+1)*11], 2)
    #print(str(index))
    wordlist.append(index_list[index])

phrase = " ".join(wordlist)
print(phrase)

#TO SEED
normalized_mnemonic = unicodedata.normalize("NFKD", phrase)
password = ""
normalized_passphrase = unicodedata.normalize("NFKD", password)

passphrase = "mnemonic" + normalized_passphrase
mnemonic = normalized_mnemonic.encode("utf-8")
passphrase = passphrase.encode("utf-8")

bin_seed = hashlib.pbkdf2_hmac("sha512", mnemonic, passphrase, 2048)
print(binascii.hexlify(bin_seed[:64]))