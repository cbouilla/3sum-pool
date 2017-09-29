import pickle
import os.path
import os

from twisted.logger import Logger

from metrology import Metrology

from singleton import Singleton

WORKER_FILE = "/mnt/large/stats.bin"
BLOCK_FILE = "/mnt/large/blocks.bin"
LOG_DIR = "/mnt/large"

#WORKER_FILE = "stats.bin"
#BLOCK_FILE = "blocks.bin"
#LOG_DIR = "."

class ShareDB(metaclass=Singleton):
    """store mined shares in a binary file"""
    block_file = None
    n = None
    rate = None

    def __init__(self):
        self.n = os.path.getsize(BLOCK_FILE) // 16
        self.block_file = open(BLOCK_FILE, 'ab')
        self.rate = Metrology.meter('shares')

    def flush(self):
        self.block_file.flush()
        os.fsync()

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
