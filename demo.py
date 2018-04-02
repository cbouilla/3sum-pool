#!/usr/bin/env python3

from share import Share, JOB_TYPES
from binascii import hexlify
from hashlib import sha256

shares = [
# 116 
Share("819b4c00", "4964d454", "59faeeac", kind=0, D=16, extranonce1="5f74243c"), 
Share("ba751500", "205e8f23", "5a2af262", kind=2, D=16, extranonce1="741e1816"),
Share("1f733300", "b186b993", "5a4da9e2", kind=1, D=16, extranonce1="741e1816")

# 113
#Share("f1e63600", "4936e33c", "59d9cf84", kind=2, D=17, extranonce1="88f3570c"),
#Share("8d399200", "edb24791", "adaaaaba", kind=0, D=17, extranonce1="dc25a3be"),
#Share("9e920a00", "5c05c84c", "59db3d24", kind=1, D=17, extranonce1="88f3570c")

# 107
# Share("ccb30200", "07176dde", "59f6354c", kind=1, D=16, extranonce1="5f74243c"),
# Share("c2013400", "04d5e22d", "5a1c266f", kind=2, D=16, extranonce1="4d6d2330"),
# Share("a27b1200", "1c8e3b4d", "5a1cf95f", kind=0, D=16, extranonce1="4d6d2330"),
]
hashes = [sha256(sha256(x.block()).digest()).digest() for x in shares]

xor = bytes([hashes[0][i] ^ hashes[1][i] ^ hashes[2][i] for i in range(32)])


print('  sha256({})'.format(sha256(shares[0].block()).hexdigest()))
print('^ sha256({})'.format(sha256(shares[1].block()).hexdigest()))
print('^ sha256({})'.format(sha256(shares[2].block()).hexdigest()))
print('  ========================================================================')
print('         {}'.format(hexlify(xor).decode()))
print()
N = int.from_bytes(xor, byteorder="big")
i = 0
while N & 1 == 0:
    i += 1
    N >>= 1
print("3SUM on {} bits".format(i))
print("3SUM on {} bits".format(256 - N.bit_length()))
print()
print("hash preimages : ")
print('  sha256d({})'.format(hexlify(shares[0].block())))
print('^ sha256d({})'.format(hexlify(shares[1].block())))
print('^ sha256d({})'.format(hexlify(shares[2].block())))


