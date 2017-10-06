#!/usr/bin/env python3
import struct
import sys
from hashlib import sha256
from binascii import hexlify, unhexlify

# dump an OLD-STYLE block file (without nTime) in ASCII-hex, one block/line (suitable for unix sort)

def sha256d(x):
    return sha256(sha256(x).digest()).digest()

def swap_endian_words(hex_words):
    '''Swaps the endianness of a hexidecimal string of words and converts to binary string.'''
    message = unhexlify(hex_words)
    if len(message) % 4 != 0: raise ValueError('Must be 4-byte word aligned')
    return b''.join([ message[4 * i: 4 * i + 4][::-1] for i in range(0, len(message) // 4) ])


def version_prev_block(kind):
    """Return the "block version" & the "hash of previous block" according to our categories (FOO, BAR, FOOBAR)"""
    if kind == 0: # 'FOO'
        block_version = hexlify(b'-OOF').decode()
        prev_block_hash = hexlify(swap_endian_words(hexlify(b'             Charles Bouillaguet'))).decode()
    elif kind == 1: # 'BAR'
        block_version = hexlify(b'-RAB').decode()
        prev_block_hash = hexlify(swap_endian_words(hexlify(b'             Pierre-Alain Fouque'))).decode()
    elif kind == 2: # 'FOOBAR'
        block_version = hexlify(b'BOOF').decode()
        prev_block_hash = hexlify(swap_endian_words(hexlify(b'AR-             Claire Delaplace'))).decode()        
    return (block_version, prev_block_hash)


class Share:
    extranonce1 = None
    extranonce2 = None
    nonce = None

    D = None                  # actual difficulty of the share
    kind = None               # 0==FOO, 1==BAR, 2==FOOBAR

    ndiff = "efbeadde"   # network time
    ntime =  None

    extraNonce2_size = 4
    coinbase_1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008"
    coinbase_2 = "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000"
      
    def __init__(self, extranonce2, nonce, ntime = "adaaaaba", job_context=None, kind=None, D=None, extranonce1=None):
        self.extranonce2 = extranonce2
        self.nonce = nonce
        self.ntime = ntime
        if job_context:
            self.extranonce1 = job_context.extranonce1
            self.kind = job_context.kind
            self.D = job_context.D
        else:
            self.extranonce1 = extranonce1
            self.kind = kind
            self.D = D

    def block(self):
        """build the (binary) block this shares represent"""

        block_version, prev_block_hash = version_prev_block(self.kind)
        coinbase = self.coinbase_1 + self.extranonce1 + self.extranonce2 + self.coinbase_2
        #print("coinbase : {}".format(coinbase))
        coinbase_hash_bin = sha256d(unhexlify(coinbase))
        merkle_root = hexlify(coinbase_hash_bin)
        version_bin = struct.pack("<I", int(block_version, base=16))
        prev_hash_bin = swap_endian_words(prev_block_hash)  # must be LE
        mrt_bin = unhexlify(merkle_root)                          # must be LE
        time_bin = struct.pack("<I", int(self.ntime, base=16))
        diff_bin = struct.pack("<I", int(self.ndiff, base=16))
        nonce_bin = struct.pack("<I", int(self.nonce, base=16))
        return version_bin + prev_hash_bin + mrt_bin + time_bin + diff_bin + nonce_bin

    def block_hash(self):
        return sha256d(self.block())

    def valid(self):
        block_hash = self.block_hash()
        return block_hash[28:] == bytes([0,0,0,0])

    def serialize(self):
        """dump this share into 160 bits"""
        return struct.pack('<HHIIII', self.kind, self.D, int(self.extranonce2, base=16), 
            int(self.extranonce1, base=16), int(self.nonce, base=16), int(self.ntime, base=16))

    @staticmethod
    def unserialize(buf):
        """Generate a Share object given a 128-bit serialized share"""
        kind, D, extranonce2_bin, extranonce1_bin, nonce_bin = struct.unpack('<HHIII', buf)
        extranonce1 = "{:08x}".format(extranonce1_bin)
        extranonce2 = "{:08x}".format(extranonce2_bin)
        nonce = "{:08x}".format(nonce_bin)
        return Share(extranonce2, nonce, D=D, kind=kind, extranonce1=extranonce1)



if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("USAGE: python3 dump_with_time.py [filename_in] [filename_out]")
        sys.exit(1)

    i = 0
    with open(sys.argv[1], 'rb') as f, open(sys.argv[2], 'wb') as g:
        while True:
            blob = f.read(16)
            if not blob:
                break

            s = Share.unserialize(blob)
            if not s.valid():
                print("Invalid block {}! bad hash".format(i))
            g.write(hexlify(s.serialize()) + b"\n")

            if i & 0xfff == 0:
                print("Done {}".format(i), end='\r', flush=True)
            i += 1

    print()