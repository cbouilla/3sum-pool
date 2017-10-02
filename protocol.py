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

from metrology import Metrology
from twisted.internet import reactor, protocol, endpoints
from twisted.protocols import basic
from twisted.logger import Logger

from worker import Worker
from share import JobContext, Share
from persistence import ShareDB, WorkerDB

class StratumProtocol(basic.LineOnlyReceiver):
    """This object holds the state of the stratum protocol (RPC ID, session_id).
       One instance exists per connection (ie per mining device).
       This objects holds ephemeral state"""
    session_id = None
    extranonce1 = None
    job_context = None
    difficulty = None
    worker = None
    job_id = 1
    rpc_id = 1
    peer = None
    log = Logger()

    # for LineOnlyReceiver
    delimiter = b'\n'

    def __init__(self, factory):
        self.factory = factory

    def __str__(self):
        try:
            return "{}".format(self.transport.getPeer())
        except:
            return "???"

    ############## handling the requests
    def connectionMade(self):
        self.log.debug("connection established from {log_source}")
        self.factory.active_connections.add(self)
        self.factory.miner_count += 1
        self.peer = self.transport.getPeer()

    def connectionLost(self, reason):
        self.log.debug("connection lost from {log_source} / {peer}", peer=self.peer)
        self.factory.miner_count -= 1
        try:
            self.factory.active_connections.remove(self)
        except Exception as e:
            self.log.warn("bizarre {log_source}: {e}", e=e)


    def lineReceived(self, line):
        self.log.debug("{log_source} <--- {line}", line=line)
        try:
            rpc = json.loads(line.strip().decode())
        except:
            self.log.warn("JSON parse error ({line})", line=line)
            return

        if 'method' not in rpc:
            #self.log.debug("got response ({line})", line=line)
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
        self.log.debug('{log_source} ---> {encoded}', encoded=encoded)
        self.transport.write(encoded)


    def subscribe(self, mining_software=None, session_id=None):
        """When the miner sends the "subscribe" RPC. The extranonce1 is chosen randomly and stored inside self"""
        if not session_id:
            session_id = str(uuid.uuid4())
            self.log.info("subscribe from {log_source} [{mining_software}] --> {session_id}", mining_software=mining_software, session_id=session_id)
        else:
            self.log.info("re-subscribe from {log_source} [{mining_software} / {session_id}]", mining_software=mining_software, session_id=session_id)
        self.session_id = session_id
        self.extranonce1 = "{:08x}".format(hash(session_id) & 0xffffffff)
        return [[['mining.notify', session_id]], self.extranonce1, 4]   # 4 = extranonce2_size


    def authorize(self, username, password):
        """When the miner sends the "authorize" RPC. This creates a new Worker object, and associates it with this connection"""
        self.log.info("authorize from {log_source} [{username} / {password}]", username=username, password=password)
        self.worker = Worker(self, username, password)
        return True


    def notify(self, cancel_older_jobs=True):
        """Send the "notify" RPC to initiate new work. Initialize a JobContext, which chooses randomly between FOO, BAR and FOOBAR"""
        self.job_id += 1
        self.job_context = JobContext(self.extranonce1, self.difficulty)
        params = [str(self.job_id)] + self.job_context.work_parameters() + [cancel_older_jobs]
        self.log.debug("notify {log_source} --- {params}", peer=self.peer, params=params)
        message = {'method': 'mining.notify', 'params': params, 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)


    def submit(self, worker_name, job_id, extranonce2, ntime, nonce):
        """when the miner sends the "submit" RPC. We ***always*** accept, in order not to confuse miners."""
        share = Share(extranonce2, nonce, job_context=self.job_context)
        if job_id != str(self.job_id):
            self.log.info("stale share {share} from {log_source}", share=share)
            return True
        valid = share.valid()
        if not valid:
            self.log.warn("invalid share {share} from {log_source}", share=share)
            return True
        self.log.debug("valid share {share} from {log_source} ", share=share)
        ShareDB().save(share)
        self.worker.submit()
        return True


    def ping(self):
        """Send the "client.get_version" RPC... and ignore the result."""
        self.log.debug("ping {log_source}")
        self.rpc_id += 1
        message = {'id': self.rpc_id, 'method': 'client.get_version', 'params': None, 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)


    def set_difficulty(self, difficulty=1):
        """Send the "set_difficulty" RPC to the miner. Save it into self."""
        self.difficulty = difficulty
        self.log.debug("set_difficulty {difficulty} to {log_source}", difficulty=difficulty)
        message = {'method': 'mining.set_difficulty', 'params': [difficulty], 'error': None}
        encoded = json.dumps(message).encode() + b'\n'
        self.transport.write(encoded)



class StratumFactory(protocol.Factory):
    """Hold the global state of the Stratum server"""
    log = Logger(namespace="Stratum")
    active_connections = {}

    def __init__(self):
        self.miner_count = 0
        self.share_per_s = Metrology.meter('shares')
        self.active_connections = set()

    def buildProtocol(self, addr):
        return StratumProtocol(self)

    def ping(self):
        """send a ping to all connected workers. This mostly helps cpuminer to not drop the connection."""
        self.log.debug("cron : ping")
        for proto in self.active_connections:
            proto.ping()

    def rotate_job(self):
        """send a notify() to all connected workers. 
           This randomly change between FOO, BAR and FOOBAR and maintain balance between the three.
        """
        self.log.debug("cron : job_rotate")
        for proto in self.active_connections:
            proto.notify()