import pickle
import logging
import struct
import sys
import time
import uuid
import json
from hashlib import sha256
from binascii import hexlify, unhexlify
import os.path
import random

BLOCK_FILE = "blocks.bin"
JOB_TYPES = ['FOO', 'BAR', 'FOOBAR']

class WorkFactory:
    """This class produces stratum jobs parameters, which are then sent to the miners by a notify() RPC call"""
   ######################""" work parameters
    extraNonce2_size = 4
    coinbase_1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008"
    coinbase_2 = "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000"
    merkle_branches = []
    nbits = "efbeadde"  # proof of honesty
    ntime = "adaaaaba"

    # job_kind and job_code are redundant
    def __init__(self, version, extranonce1):
        self.job_id = 0
        self.difficulty = 1
        self.extranonce1 = extranonce1

        # non-constant work parameters
        if version == 'FOO':
            self.block_version = hexlify(b'-OOF').decode()
            self.prev_block_hash = hexlify(Share.swap_endian_words(hexlify(b'This is a ~random 32-byte string'))).decode()
            self.job_kind = "foo"
            self.job_code = 0
        elif version == 'BAR':
            self.block_version = hexlify(b'-RAB').decode()
            self.prev_block_hash = hexlify(Share.swap_endian_words(hexlify(b'This is a ~random 32-byte string'))).decode()    
            self.job_kind = "bar"
            self.job_code = 1
        elif version == 'FOOBAR':
            self.block_version = hexlify(b'BOOF').decode()
            self.prev_block_hash = hexlify(Share.swap_endian_words(hexlify(b'AR-This is a rndm 32-byte string'))).decode()    
            self.job_kind = "foobar"
            self.job_code = 2


    def get_jobid(self):
        self.job_id += 1
        return "{}-{}".format(self.job_kind, self.job_id)

    def work_notify(self, cancel_older_jobs=True):
        return [self.get_jobid(), self.prev_block_hash, self.coinbase_1, self.coinbase_2, \
                self.merkle_branches, self.block_version, self.nbits, self.ntime, cancel_older_jobs]


class Share:
    @staticmethod
    def sha256d(x):
        return sha256(sha256(x).digest()).digest()

    @staticmethod
    def swap_endian_words(hex_words):
      '''Swaps the endianness of a hexidecimal string of words and converts to binary string.'''
      message = unhexlify(hex_words)
      if len(message) % 4 != 0: raise ValueError('Must be 4-byte word aligned')
      return b''.join([ message[4 * i: 4 * i + 4][::-1] for i in range(0, len(message) // 4) ])

    
    def __init__(self, factory, extranonce2, nonce):
        self.factory = factory
        self.extranonce2 = extranonce2
        self.ntime = factory.ntime
        self.nonce = int(nonce, base=16)
        self.job_code = factory.job_code
        self.difficulty = factory.difficulty  # WARNING: this can be per-job
        # build the block
        coinbase = factory.coinbase_1 + factory.extranonce1 + extranonce2 + factory.coinbase_2
        coinbase_hash_bin = Share.sha256d(unhexlify(coinbase))
        merkle_root = hexlify(coinbase_hash_bin)
        version_bin = struct.pack("<I", int(factory.block_version, base=16))
        prev_hash_bin = Share.swap_endian_words(factory.prev_block_hash)  # must be LE
        mrt_bin = unhexlify(merkle_root)            # must be LE
        time_bin = struct.pack("<I", int(factory.ntime, base=16))
        bits_bin = struct.pack("<I", int(factory.nbits, base=16))
        nonce_bin = struct.pack("<I", self.nonce)
        self.block = version_bin + prev_hash_bin + mrt_bin + time_bin + bits_bin + nonce_bin

    def __str__(self):
        return "({} / {} / {} / {} / {})".format(self.job_code, self.difficulty, self.extranonce2, self.ntime, self.nonce)

    def block_hash(self):
        return Share.sha256d(self.block)

    def valid(self):
        block_hash = self.block_hash()
        return block_hash[28:] == bytes([0,0,0,0])

    def formated_hex_block(self):
        h = hexlify(self.block).decode()
        return "{} {} {} {} {} {}".format(h[0:8], h[8:72], h[72:136], h[136:144], h[144:152], h[152:160])

    def serialize(self):
        return struct.pack('<HHIII', self.job_code, self.difficulty, int(self.extranonce2, base=16), int(self.factory.extranonce1, base=16), self.nonce)

    @staticmethod
    def unserialize(buf):
        job_code, difficulty, extranonce2_bin, extranonce1_bin, nonce_bin = struct.unpack('<HHIII', buf)
        extranonce1 = "{:08x}".format(extranonce1_bin)
        work_factory = WorkFactory(JOB_TYPES[job_code], extranonce1)

        extranonce2 = "{:08x}".format(extranonce2_bin)
        nonce = "{:08x}".format(nonce_bin)
        return Share(work_factory, extranonce2, nonce)


N = [0, 0, 0]
i = 0
print("block file is {} bytes".format(os.path.getsize(BLOCK_FILE)))
print("Expecting {} complete blocks".format(os.path.getsize(BLOCK_FILE) // 16))
with open(BLOCK_FILE, 'rb') as f:
    while True:
        b = f.read(16)
        if b == bytes():
            break
        if len(b) != 16:
            print("Incomplete block {}! Just read {} bytes".format(i, len(b)))
            sys.exit(1)
        s = Share.unserialize(b)
        N[s.job_code] += 1
        if not s.valid():
            print("Invalid block {}! bad hash".format(i))
        i += 1
        print("Checking block {}".format(i), end='\r', flush=True)
print()
print("Successfully read {} blocks. FOO / BAR / FOOBAR : {}".format(i, N))