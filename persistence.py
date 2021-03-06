import pickle
import os.path
import os

from twisted.logger import Logger

from rate import RateMeter


WORKDIR = '/mnt/large/'

WORKER_FILE = WORKDIR + "stats.bin"
BLOCK_FILE = WORKDIR + "blocks11.bin"
STRATUM_LOG = WORKDIR + 'stratum11.log'
ACCESS_LOG = WORKDIR + 'access.log'



class Singleton(type):
    """
    Define an Instance operation that lets clients access its unique
    instance.
    """
    def __init__(cls, name, bases, attrs, **kwargs):
        super().__init__(name, bases, attrs)
        cls._instance = None

    def __call__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__call__(*args, **kwargs)
        return cls._instance


class ShareDB(metaclass=Singleton):
    """store mined shares in a binary file"""
    block_file = None
    n = None
    rate = RateMeter()

    def __init__(self):
        try:
            self.n = os.path.getsize(BLOCK_FILE) // 16
        except FileNotFoundError:
            self.n = 0
        self.block_file = open(BLOCK_FILE, 'ab')
        self.rate = RateMeter()


    def flush(self):
        self.block_file.flush()

    def save(self, share):
        self.block_file.write(share.serialize())
        self.rate.mark()
        self.n += 1

    def get(self, i):
        if i >= self.n:
            return ValueError("i too large")
        with open(BLOCK_FILE, 'rb') as f:
            f.seek(i * 16)
            buf = f.read(16)
        return Share.unserialize(buf)

    def stop(self):
        self.block_file.close()



class PersistentWorkerState:
    """Data saved accross connections and server restarts"""
    name = None
    kind = None
    total_shares = 0            # total number of shares submitted
    diff1_shares = 0            # sum for each submitted share, of cuberoot(D)
    optimal_difficulty = None   # difficulty maximizing (cuberoot(D) * Rate)
    maximum_hashrate = None     # hashrate at large difficulty

    def submit(self):
        """invoked by the Worker when a new share is submitted"""
        self.total_shares += 1
        if self.optimal_difficulty:
            self.diff1_shares += self.optimal_difficulty ** (1/3)

    def set_maximum_hashrate(self, h):
        self.maximum_hashrate = h
        WorkerDB().flush()

    def set_optimal_difficulty(self, d):
        self.optimal_difficulty = d
        WorkerDB().flush()

    def __str__(self):
        return "[Worker: {} / {}. maxhash={}, opt_D: {}. Shares, tot: {}, eq1: {}]".format(self.name, self.kind, 
            self.maximum_hashrate, self.optimal_difficulty, self.total_shares, self.diff1_shares)

class WorkerDB(metaclass=Singleton):
    workers = {}
    logger = Logger()

    def __init__(self):
        try:
            with open(WORKER_FILE, 'rb') as f:
                self.workers = pickle.load(f)
            self.logger.info('opened worker DB: {} items loaded'.format(len(self.workers)))
        except Exception as e:
            self.logger.warn('impossible to load worker db : {}'.format(e))


    def get(self, username, kind):
        key = (username, kind)
        try:
            return self.workers[key]
        except:
            state = PersistentWorkerState()
            state.name = username
            state.kind = kind
            self.workers[key] = state
            return state


    def flush(self):
        """save the DB to disk"""
        try:
            with open(WORKER_FILE, 'wb') as f:   # FIXME : save to another file before
                pickle.dump(self.workers, f)
        except Exception as e:
            self.logger.error('impossible to save worker db : {}'.format(e))


def db_cron_hourly():
    ShareDB().flush()
    WorkerDB().flush()
