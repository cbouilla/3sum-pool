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

#import metrology
from metrology import Metrology

from twisted.internet import reactor, protocol, endpoints
from twisted.protocols import basic
from twisted.logger import Logger
from twisted.web.resource import Resource, NoResource

BLOCK_FILE = "blocks.bin"
STATS_FILE = "stats.bin"
JOB_TYPES = ['FOO', 'BAR', 'FOOBAR']
HASHRATE_ESTIMATION_DIFFICULTY = 1024
HASHRATE_ESTIMATION_MINIMUM = 4

class WorkFactory:
   ######################""" work parameters
    extraNonce2_size = 4
    coinbase_1 = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008"
    coinbase_2 = "072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000"
    merkle_branches = []
    nbits = "efbeadde"  # proof of honesty
    ntime = "adaaaaba"

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


class Worker:
    """Contains:
       + the persistent state of the worker (saved accross connections)
       + methods that deal with work selection
       """
    def __init__(self, name, kind):
        self.name = name
        self.kind = kind
        self.total_shares = 0
        self.diff1_shares = 0
        self.optimal_difficulty = None   # difficulty maximizing (Difficulty**1/3 * Rate)
        self.rate = None
        self.maximum_hashrate = None     # hashrate at large difficulty
        self.state = "Starting up"
        self.connection = None

    def __getstate__(self):
        """pickler that resets volatile state"""
        state = self.__dict__.copy()
        state['connection'] = None
        state['rate'] = None
        return state

    def share_submitted(self):
        if not self.rate:
            self.rate = Metrology.meter('shares-{}'.format(self.name))
        self.rate.mark()
        self.total_shares += 1
        if hasattr(self, 'optimal_difficulty') and self.optimal_difficulty:
            self.diff1_shares += self.optimal_difficulty ** (1/3)

    def get_to_work(self):
        """A miner goes through the following states
           1) hashrate estimation
           2) optimal difficulty search
           3) production
        """
        if self.optimal_difficulty:
            self.production()
        elif self.maximum_hashrate:
            self.find_optimal_difficulty()
        else:
            self.estimate_hashrate()   

    def rate_estimation_start(self, difficulty, callback, timeout=80):
        """Set the difficulty to `difficulty`, send work and wait for `timeout` seconds. 
           Then fire `callback(difficulty, rate)`. If the rate could not be computed, it is set to None.
        """
        self.connection.set_difficulty(difficulty)
        self.connection.notify()
        reactor.callLater(timeout, self.rate_estimation_end, difficulty, callback)

    def rate_estimation_end(self, difficulty, callback):
        if not self.rate:
            self.connection.log.info("rate estimation failed for {log_source} at difficulty {difficulty}", difficulty=difficulty)
            rate = None
        else:
            rate = self.rate.one_minute_rate
            self.connection.log.info("Estimated rate of {rate} at difficulty {difficulty} for {log_source}", rate=rate, difficulty=difficulty)
        callback(difficulty, rate)


    def estimate_hashrate(self):
        def hashrate_estimation_callback(difficulty, rate):
            if rate is None or rate <= HASHRATE_ESTIMATION_MINIMUM:
                if difficulty == 1:
                    self.maximum_hashrate = 50e6     # educated guess; it's probably a CPU miner
                    hashrate_estimation_continuation()
                else:
                    # restart with lower difficulty
                    self.rate_estimation_start(max(1, difficulty//16), hashrate_estimation_callback)
            else:
                self.maximum_hashrate = rate * difficulty * (1 << 32)
                hashrate_estimation_continuation()                

        def hashrate_estimation_continuation():
            self.connection.log.info("Maximum hashrate found: {hashrate} ({log_source})", hashrate=self.maximum_hashrate)
            self.find_optimal_difficulty()

        self.state = "Estimating hashrate"
        self.connection.log.info("starting maximum hashrate estimation ({log_source})")
        self.rate_estimation_start(HASHRATE_ESTIMATION_DIFFICULTY, hashrate_estimation_callback)


    def find_optimal_difficulty(self):
        def optimal_difficulty_callback(difficulty, rate):
            if rate is None:
                # stop search, difficulty too high, exploit previous results
                optimal_difficulty_continuation()
                return
            else:
                self.difficulty_search[difficulty] = rate
                hashrate = rate * difficulty * (1 << 32)
                objective = rate * (difficulty**(1/3))
                # stop if we are at 95% of full hashrate and objective function is decreasing
                if hashrate >= 0.95 * self.maximum_hashrate and objective <= 0.95 * self.difficulty_best_objective:
                    optimal_difficulty_continuation()
                    return
                self.difficulty_best_objective = max(self.difficulty_best_objective, objective)
                self.rate_estimation_start(difficulty+1, optimal_difficulty_callback)

        def optimal_difficulty_continuation():
            best_objective = 1
            best_difficulty = 1
            for difficulty, rate in self.difficulty_search.items():
                objective = rate * (difficulty**(1/3))
                if objective > best_objective:
                    best_objective = objective
                    best_difficulty = difficulty

            self.connection.log.info("Optimal difficulty: {difficulty}, with objective={objective:.1f} ({log_source})", 
                difficulty=best_difficulty, objective=best_objective)
            self.optimal_difficulty = best_difficulty
            self.production()

        self.connection.log.info("starting optimal difficulty search ({log_source})")
        self.state = "Finding optimal difficulty"
        self.difficulty_search = {}
        self.difficulty_best_objective = 0
        self.rate_estimation_start(1, optimal_difficulty_callback)

    def production(self):
        self.state = "Production"
        self.connection.log.info("going into production ({log_source}) at difficulty {difficulty}", difficulty=self.optimal_difficulty)
        self.connection.set_difficulty(self.optimal_difficulty)
        self.connection.notify()


#assert WorkFactory("toto").buildShare("00000000", "595a4dbe", "b59e23c3").valid()
#assert WorkFactory().buildShare("01000000", "baaaaaad", "e5ab4003").valid()

class StratumProtocol(basic.LineOnlyReceiver):
    """This object holds the state of the stratum protocol (RPC ID, session_id).
       The extranonce1 is derived from the session_id."""
    log = Logger()
    delimiter = b'\n'

    def __init__(self, factory):
        self.factory = factory
        self.worker = None
        self.rpc_id = 1
        #self.last_active = None
        #self.share_per_s = None

    def __str__(self):
        try:
            return "{}".format(self.transport.getPeer())
        except:
            return "???"

    ############## handling the requests
    def connectionMade(self):
        self.log.debug("connection established from {log_source}")
        self.factory.active_connections.add(self)
        self.factory.miner_count.increment()
        self.peer = self.transport.getPeer()

    def connectionLost(self, reason):
        # log the deconnection
        self.log.debug("connection lost from {log_source} / {peer}", peer=self.peer)
        self.factory.miner_count.decrement()
        try:
            self.factory.active_connections.remove(self)
        except Exception as e:
            self.log.warn("bizarre {log_source}: {e}", e=e)


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
        if not session_id:
            session_id = str(uuid.uuid4())
            self.log.info("subscribe from {log_source} [{mining_software}] --> {session_id}", mining_software=mining_software, session_id=session_id)
        else:
            self.log.info("re-subscribe from {log_source} [{mining_software} / {session_id}]", mining_software=mining_software, session_id=session_id)
        self.session_id = session_id
        extranonce1 = "{:08x}".format(hash(session_id) & 0xffffff)
        self.work_factory = WorkFactory(random.choice(JOB_TYPES), extranonce1)
        return [[['mining.notify', session_id]], self.work_factory.extranonce1, self.work_factory.extraNonce2_size]


    def authorize(self, username, password):
        self.log.info("authorize from {log_source} [{username} / {password}]", username=username, password=password)
        try:
            self.worker = self.factory.workers[username]
        except KeyError:
            self.worker = Worker(username, password)
            self.factory.workers[username] = self.worker
            self.log.info('registering new worker {worker}', worker=self.worker)
        self.worker.connection = self
        reactor.callLater(0.5, self.worker.get_to_work)
        return True


    def notify(self, cancel_older_jobs=True):
        params = self.work_factory.work_notify(cancel_older_jobs)  
        self.log.debug("notify {log_source}", params=params)
        message = {'method': 'mining.notify', 'params': params, 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)
        self.worker.rate = None

    def submit(self, worker_name, job_id, extranonce2, ntime, nonce):
        # check whether the share is valid
        share = Share(self.work_factory, extranonce2, nonce)
        valid = share.valid()
        if not valid:
            self.log.warn("invalid share submitted from {log_source} [{share}]", share=share)
            return False
        
        self.log.info("valid share submitted from {log_source} [{share}]", share=share)
        self.factory.save_share(share)
        self.worker.share_submitted()
        return True

    def ping(self):
        self.log.debug("sending ping to {log_source}")
        self.rpc_id += 1
        message = {'id': self.rpc_id, 'method': 'client.get_version', 'params': None, 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)

    def set_difficulty(self, difficulty=1):
        self.log.debug("set_difficulty {log_source}, new_difficulty={difficulty}", difficulty=difficulty)
        message = {'method': 'mining.set_difficulty', 'params': [difficulty], 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)


class StratumFactory(protocol.Factory):
    """Hold the global state of the Stratum server"""
    log = Logger(namespace="Stratum")
    block_file = None
    workers = {}

    def __init__(self):
        # miners we must send work to
        self.miner_count = Metrology.counter('active-miners')
        self.share_per_s = Metrology.meter('shares')
        self.active_connections = set()

    def buildProtocol(self, addr):
        return StratumProtocol(self)

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

    def stopFactory(self):
        self.block_file.close()
        try:
            with open(STATS_FILE, 'wb') as f:
                pickle.dump(self.workers, f)
        except Exception as e:
            self.log.error('impossible to save stats : {}'.format(e))



class NavBarStats(Resource):
    """the HTTP server that responds to JSON requests from clients for the navbar"""
    isLeaf = True

    def __init__(self, factory):
        super(NavBarStats, self).__init__()
        self.factory = factory

    def render_GET(self, request):
        '''hack using JSONP'''
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        d = {}
        d['miners'] = self.factory.miner_count.count
        d['rate'] = self.factory.share_per_s.one_minute_rate
        d['shares'] = os.path.getsize(BLOCK_FILE) // 16 # each share is stored on 16 bytes
        return b'jsonNavbarCallback(' + json.dumps(d).encode() + b');'


class WorkerStats(Resource):
    isLeaf = True
    def __init__(self, factory):
        super(WorkerStats, self).__init__()
        self.factory = factory

    def render_GET(self, request):
        '''hack using JSONP'''
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        L = []
        for name, worker in self.factory.workers.items():
            d = {}
            d['name'] = name
            d['kind'] = worker.kind
            d['total_shares'] = worker.total_shares
            d['diff1_shares'] = worker.diff1_shares
            d['state'] = worker.state
            if worker.maximum_hashrate:
                d['maximum_hashrate'] = worker.maximum_hashrate
            else:
                d['maximum_hashrate'] = 0
            if worker.optimal_difficulty:
                d['D'] = worker.optimal_difficulty
            else:
                d['D'] = '???'
            if worker.rate:
                d['rate'] = worker.rate.one_minute_rate
            else:
                d['rate'] = 'offline'
            L.append(d)
        return b'jsonWorkerCallback(' + json.dumps(L).encode() + b');'


class ShareView(Resource):
    isLeaf = True
    def __init__(self, i):
        super(ShareView, self).__init__()
        self.i = i

    def render_GET(self, request):
        '''hack using JSONP'''
        # validate i
        d = {'i': self.i}
        with open(BLOCK_FILE, 'rb') as f:
            f.seek(self.i * 16)
            buf = f.read(16)
        share = Share.unserialize(buf)
        d['block_hex'] = hexlify(share.block).decode()
        d['hash']  = hexlify(share.block_hash()).decode()
        d['block_ascii']  = share.block.decode('ascii', errors='replace')
        return b'jsonShareCallback(' + json.dumps(d).encode() + b');'


class ShareDispatch(Resource):
    def getChild(self, name, request):
        try:
            i = int(name)
            n_shares = os.path.getsize(BLOCK_FILE) // 16
            if i >= n_shares:    
                raise ValueError
            return ShareView(i)
        except:
            return NoResource()
        


class  StratumSite(Resource):
    def __init__(self, factory):
        super(StratumSite, self).__init__()
        self.factory = factory

    def getChild(self, name, request):
        print("getchild {}".format(name))
        if name == b'navbar':
            return NavBarStats(self.factory)
        elif name == b'workers':
            return  WorkerStats(self.factory)
        elif name == b'share':
            return  ShareDispatch()

class StratumCron:
    """invoqued periodically"""
    def __init__(self, factory):
        self.factory = factory

    def minute(self):
        # log progress ?
        try:
            self.factory.block_file.flush()
        except:
            log.error("Couldn't flush block file")

        for conn in self.factory.active_connections:
            conn.ping()

#
# N_k blocs avec k bits à zéro (k >= 32)
#
# [2**(32/3) * N_32] ** 3 == 2**n 
# [2**(36/3) * N_36] ** 3 == 2**n 
#
# sum_k 2**(k/3) * N_k == 2**n
