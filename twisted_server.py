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

import metrology
from metrology import Metrology
from metrology.reporter.logger import LoggerReporter as MetrologyReporter

from twisted.internet import reactor, protocol, endpoints
from twisted.protocols import basic
from twisted.logger import Logger
from twisted.web import resource

BLOCK_FILE = "blocks.bin"
STATS_FILE = "stats.bin"

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

    
    def __init__(self, factory, extranonce2, ntime, nonce):
        self.factory = factory
        self.extranonce2 = extranonce2
        self.ntime = int(ntime, base=16)
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
        time_bin = struct.pack("<I", self.ntime)
        bits_bin = struct.pack("<I", int(factory.nbits, base=16))
        nonce_bin = struct.pack("<I", self.nonce)
        self.block = version_bin + prev_hash_bin + mrt_bin + time_bin + bits_bin + nonce_bin

    def __str__(self):
        return "({} / {} / {} / {:08x} / {:08x})".format(self.job_code, self.difficulty, self.extranonce2, self.ntime, self.nonce)

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



class Worker:
    """Contains the persistent state of the worker (saved accross connections)"""
    def __init__(self, name, kind):
        self.name = name
        self.kind = kind
        self.total_shares = 0
        self.optimal_difficulty = None

#assert WorkFactory("toto").buildShare("00000000", "595a4dbe", "b59e23c3").valid()
#assert WorkFactory().buildShare("01000000", "baaaaaad", "e5ab4003").valid()

class StratumProtocol(basic.LineOnlyReceiver):
    """This object holds the state of the stratum protocol (RPC ID, session_id).
       The extranonce1 is derived from the session_id."""
    log = Logger()
    delimiter = b'\n'

    ######################""" work parameters
    extraNonce2_size = 4
    coinbase_1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008"
    coinbase_2 = "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000"
    merkle_branches = [] # easier this way
    nbits = "deadbeef"  # proof of honesty
    ntime = "baaaaaad"
    
    def get_jobid(self):
        self.job_id += 1
        return "{}-{}".format(self.job_kind, self.job_id)

    def __init__(self, factory):
        self.factory = factory
        self.worker = None
        self.rpc_id = 1
        self.last_active = None
        self.share_per_s = None

        # work parameters
        self.block_version = hexlify(b'FOO-').decode()
        self.prev_block_hash = hexlify(b'This is a ~random 32-byte string').decode()
        self.job_id = 0
        self.job_kind = "foo"
        self.job_code = 0
        self.difficulty = 1


    def __str__(self):
        try:
            return "{}".format(self.transport.getHost())
        except:
            return "???"

    ############## handling the requests
    def connectionMade(self):
        self.log.debug("connection established from {log_source}")
        self.factory.active_connections.add(self)
        self.factory.miner_count.increment()

    def connectionLost(self, reason):
        # log the deconnection
        self.log.debug("connection lost from {log_source}")
        self.factory.miner_count.decrement()
        try:
            self.active_connections.remove(self)
        except:
            self.log.warn("bizarre {log_source}")


    def lineReceived(self, line):
        #self.log.debug("received from {log_source}: {line}", line=line)

        try:
            rpc = json.loads(line.strip().decode())
        except:
            self.log.warn("JSON parse error ({line})", line=line)
            return

        if 'method' not in rpc:
            self.log.debug("got response ({line})", line=line)
            return

        if 'params' not in rpc:
            self.log.warn("Request without params ({line})", line=line)
            return

        if 'id' not in rpc:
            self.log.warn("Request without id ({line})", line=line)
            return

        if rpc['method'] == 'mining.subscribe':
            output = self.subscribe(*rpc['params'])
        elif rpc['method'] == 'mining.authorize':
            output = self.authorize(*rpc['params'])
        elif rpc['method'] == 'mining.submit':
            output = self.submit(*rpc['params'])
        else:
            self.log.warn("Unkown method ({line})", line=line)
            return

        response = {'id': rpc['id'], 'result': output, 'error': None}
        encoded = json.dumps(response).encode() + b'\n'
        #self.log.debug('sending to {log_source}: {encoded}', encoded=encoded)
        self.transport.write(encoded)


    def subscribe(self, mining_software=None, session_id=None):
        self.log.info("subscribe from {log_source} [{mining_software} / {session_id}]", mining_software=mining_software, session_id=session_id)
        if not session_id:
            session_id = str(uuid.uuid4())
        self.session_id = session_id        
        self.extranonce1 = "{:08x}".format(hash(session_id) & 0xffffff)
        return [[['mining.notify', session_id]], self.extranonce1, self.extraNonce2_size]


    def authorize(self, username, password):
        self.log.info("authorize from {log_source} [{username} / {password}]", username=username, password=password)
        # try to fetch the worker from the global database
        # if it fails, create it
        try:
            self.worker = self.factory.workers[username]
        except KeyError:
            self.worker = Worker(username, password)
            self.log.info('registering new worker {worker}', worker=self.worker)
        self.share_per_s = Metrology.meter('shares-{}'.format(username))
        
        reactor.callLater(0.5, self.notify)
        return True

    def submit(self, worker_name, job_id, extranonce2, ntime, nonce):
        # check whether the share is valid
        share = Share(self, extranonce2, ntime, nonce)
        valid = share.valid()
        if not valid:
            self.log.warn("invalid share submitted from {log_source} [{share}]", share=share)
            return False
        
        self.log.info("valid share submitted from {log_source} [{share}]", share=share)
        self.share_per_s.mark()
        self.factory.save_share(share)
        return True

    def ping(self):
        self.log.debug("sending ping to {log_source}")
        self.rpc_id += 1
        message = {'id': self.rpc_id, 'method': 'client.get_version', 'params': None, 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)


    def notify(self, cancel_older_jobs=True):
        params=  [self.get_jobid(), self.prev_block_hash, self.coinbase_1, self.coinbase_2, \
                 self.merkle_branches, self.block_version, self.nbits, self.ntime, cancel_older_jobs]
        self.log.debug("notify {log_source}", params=params)        
        message = {'method': 'mining.notify', 'params': params, 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)


    def set_difficulty(self, difficulty=1):
        self.log.debug("set_difficulty {log_source}, new_difficulty={difficulty}", difficulty=difficulty)
        message = {'method': 'mining.set_difficulty', 'params': [difficulty], 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)


class LogWrapper(Logger):
    def __init__(self, *args, **kwargs):
        super(LogWrapper, self).__init__(*args, **kwargs)

    def log(self, level, *args, **kwargs):
        self.info(*args, **kwargs)



class StratumFactory(protocol.Factory):
    """Hold the global state of the Stratum server"""
    log = LogWrapper(namespace="Stratum")
    block_file = None
    workers = {}
    active_connections = set()

    def __init__(self):
        # miners we must send work to
        self.miner_count = Metrology.counter('active-miners')
        self.share_per_s = Metrology.meter('shares')
        self.metrology_reporter = MetrologyReporter(level=logging.DEBUG, logger=self.log, interval=10)

    def buildProtocol(self, addr):
        return StratumProtocol(self)

    def wake_clients(self):
        for conn in self.active_connections:
            #conn.check_activity()
            #conn.ping()
            pass

    def save_share(self, share):
        self.block_file.write(share.serialize())
        self.share_per_s.mark()

    def startFactory(self):
        self.block_file = open(BLOCK_FILE, 'ab')
        try:
            with open(STATS_FILE, 'rb') as f:
                self.workers = pickle.load(f)
        except Exception as e:
            self.log.warn('impossible to load stats : {}'.format(e))
        self.metrology_reporter.start()

    def stopFactory(self):
        self.block_file.close()
        try:
            with open(STATS_FILE, 'wb') as f:
                pickle.dump(self.workers, f)
        except Exception as e:
            self.log.error('impossible to save stats : {}'.format(e))
        self.metrology_reporter.stop()



class StratumSite(resource.Resource):
    """the HTTP server that responds to JSON requests from clients"""
    def __init__(self, factory):
        self.factory = factory

    isLeaf = True
    def render_GET(self, request):
        '''hack JSONP'''
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        d = {}
        d['miners'] = self.factory.miner_count.count
        d['rate'] = self.factory.share_per_s.one_minute_rate
        d['shares'] = os.path.getsize(BLOCK_FILE) // 16 # each share is stored on 16 bytes
        return b'jsonCallback(' + json.dumps(d).encode() + b');'

