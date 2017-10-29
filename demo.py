#!/usr/bin/env python3

from share import Share, JOB_TYPES
from binascii import hexlify
from hashlib import sha256

shares = [
Share("f1e63600", "4936e33c", "59d9cf84", kind=2, D=17, extranonce1="88f3570c"),
Share("8d399200", "edb24791", "adaaaaba", kind=0, D=17, extranonce1="dc25a3be"),
Share("9e920a00", "5c05c84c", "59db3d24", kind=1, D=17, extranonce1="88f3570c")
]
hashes = [sha256(sha256(x.block()).digest()).digest() for x in shares]

xor = bytes([hashes[0][i] ^ hashes[1][i] ^ hashes[2][i] for i in range(32)])


print('  sha256({})'.format(sha256(shares[0].block()).hexdigest()))
print('^ sha256({})'.format(sha256(shares[1].block()).hexdigest()))
print('^ sha256({})'.format(sha256(shares[2].block()).hexdigest()))
print('  ========================================================================')
print('         {}'.format(hexlify(xor).decode()))
print()
print('  sha256d({})'.format(hexlify(shares[0].block())))
print('^ sha256d({})'.format(hexlify(shares[1].block())))
print('^ sha256d({})'.format(hexlify(shares[2].block())))
