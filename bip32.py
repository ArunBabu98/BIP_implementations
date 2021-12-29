import binascii
import hmac
import hashlib
import ecdsa
import struct
import base58 
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int

# chain m

seed = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")
I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
Il, Ir = I[:32], I[32:]

secret = Il
chain = Ir
xprv = binascii.unhexlify("0488ade4")
xpub = binascii.unhexlify("0488b21e")
depth = b"\x00"
fpr = b'\0\0\0\0'
index = 0 
child = struct.pack('>L', index)


k_priv = ecdsa.SigningKey.from_string(secret, curve=SECP256k1)
K_priv = k_priv.get_verifying_key()

data_priv = b'\x00' + (k_priv.to_string()) 

if K_priv.pubkey.point.y() & 1:
    data_pub= b'\3'+int_to_string(K_priv.pubkey.point.x())
else:
    data_pub = b'\2'+int_to_string(K_priv.pubkey.point.x())

raw_priv = xprv + depth + fpr + child + chain + data_priv
raw_pub = xpub + depth + fpr + child + chain + data_pub

hashed_xprv = hashlib.sha256(raw_priv).digest()
hashed_xprv = hashlib.sha256(hashed_xprv).digest()
hashed_xpub = hashlib.sha256(raw_pub).digest()
hashed_xpub = hashlib.sha256(hashed_xpub).digest()

raw_priv += hashed_xprv[:4]
raw_pub += hashed_xpub[:4]

print(base58.b58encode(raw_priv))
print(base58.b58encode(raw_pub))

