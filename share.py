import time
import struct
import random
from hashlib import sha256
from binascii import hexlify, unhexlify

JOB_TYPES = ['FOO', 'BAR', 'FOOBAR']


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


class JobContext:
    extranonce1 = None
    kind = None
    D = None

    def __init__(self, extranonce1, D):
        self.extranonce1 = extranonce1
        self.kind = random.randrange(3)
        self.D = D

    def work_parameters(self):
        block_version, prev_block_hash = version_prev_block(self.kind)
        ntime = "{:08x}".format(int(time.time()))
        return [prev_block_hash, Share.coinbase_1, Share.coinbase_2, [], block_version, Share.ndiff, ntime]


class Share:
    """representation of a full share (i.e. a block whose hash is correct)"""
    
    # variable part. Strings, in hex.
    extranonce1 = None
    extranonce2 = None
    nonce = None
    ntime = None              # network time

    # metadata
    D = None                  # actual difficulty of the share
    kind = None               # 0==FOO, 1==BAR, 2==FOOBAR

    # static values. These choices yields invalid bitcoin blocks.
    # This means that we don't actually mine bitcoins.
    ndiff = "efbeadde"   # encoded network difficulty
    

    extraNonce2_size = 4
    coinbase_1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008"
    coinbase_2 = "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000"
    
  
    def __init__(self, extranonce2, nonce, ntime, job_context=None, kind=None, D=None, extranonce1=None):
        self.extranonce2 = extranonce2
        self.nonce = nonce
        self.ntime = ntime
        self._hash = None
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
        coinbase_hash_bin = sha256d(unhexlify(coinbase))
        merkle_root = hexlify(coinbase_hash_bin)
        version_bin = struct.pack("<I", int(block_version, base=16))
        prev_hash_bin = swap_endian_words(prev_block_hash)  # must be LE
        mrt_bin = unhexlify(merkle_root)                          # must be LE
        time_bin = struct.pack("<I", int(self.ntime, base=16))
        diff_bin = struct.pack("<I", int(self.ndiff, base=16))
        nonce_bin = struct.pack("<I", int(self.nonce, base=16))
        return version_bin + prev_hash_bin + mrt_bin + time_bin + diff_bin + nonce_bin

    def __str__(self):
        return "({} / D={} / {} / {} / {})".format(JOB_TYPES[self.kind], self.D, self.extranonce1, self.extranonce2, self.nonce)

    def block_hash(self):
        if not self._hash:
            self._hash = sha256d(self.block())
        return self._hash
        

    def valid(self):
        #print(hexlify(self.block()).decode())
        #print(self.formated_hex_block())
        block_hash = self.block_hash()
        #print(hexlify(block_hash).decode())
        return block_hash[28:] == bytes([0,0,0,0])

    def formated_hex_block(self):
        h = hexlify(self.block()).decode()
        return "{} {} {} {} {} {}".format(h[0:8], h[8:72], h[72:136], h[136:144], h[144:152], h[152:160])

    def serialize(self):
        """dump this share into 160 bits"""
        return struct.pack('<HHIIII', self.kind, self.D, int(self.extranonce2, base=16), 
            int(self.extranonce1, base=16), int(self.nonce, base=16), int(self.ntime, base=16))

    @staticmethod
    def unserialize(buf):
        """Generate a Share object given a 128-bit serialized share"""
        kind, D, extranonce2_bin, extranonce1_bin, nonce_bin, ntime_bin = struct.unpack('<HHIIII', buf)
        extranonce1 = "{:08x}".format(extranonce1_bin)
        extranonce2 = "{:08x}".format(extranonce2_bin)
        nonce = "{:08x}".format(nonce_bin)
        ntime = "{:08x}".format(ntime_bin)
        return Share(extranonce2, nonce, ntime, D=D, kind=kind, extranonce1=extranonce1)

