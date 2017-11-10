from twisted.internet import reactor
from twisted.logger import Logger

from persistence import WorkerDB
from rate import RateMeter

HASHRATE_ESTIMATION_DIFFICULTY = 8192
HASHRATE_ESTIMATION_MINIMUM = 3
HASHRATE_ESTIMATION_TIMEOUT = 120
DIFFICULTY_ESTIMATION_TIMEOUT = 80

class Worker:
    """High-level view of a worker. Protocol-level details are not dealt with."""
    name = None
    kind = None
    protocol = None
    persistent = None
    rate_est = None
    log = Logger()

    def __init__(self, protocol, name, kind):
        self.name = name
        self.kind = kind
        self.protocol = protocol
        self.persistent = WorkerDB().get(name, kind)
        self.rate = RateMeter()
        reactor.callLater(0.5, self._get_to_work)

    def __str__(self):
        return "{}/{} @ {}".format(self.name, self.kind, self.protocol.peer)

    def submit(self):
        """invoked by the protocol when a share is submitted"""
        self.rate.mark()
        self.persistent.submit()
        

    def _get_to_work(self):
        """A miner goes through the following states
           1) hashrate estimation
           2) optimal difficulty search
           3) production
        """
        if self.persistent.optimal_difficulty:
            self._production()
        elif self.persistent.maximum_hashrate:
            self._find_optimal_difficulty()
        else:
            self._estimate_hashrate()   

    #### auto-tuning machinery ####
    def _rate_estimation(self, difficulty, callback, timeout=80, args={}):
        """Set the difficulty to `difficulty`, send work and wait for `timeout` seconds. 
           Then fire `callback(difficulty, rate, **args)`. If the rate could not be computed, it is None.
        """
        self.protocol.set_difficulty(difficulty)
        self.protocol.notify()
        self.rate = RateMeter()
        reactor.callLater(timeout, self._rate_estimation_end, difficulty, callback, args)

    def _rate_estimation_end(self, difficulty, callback, args):
        if self.rate.one_minute_rate() == 0:
            self.protocol.log.info("rate estimation failed for {log_source} at difficulty {difficulty}", difficulty=difficulty)
            rate = None
        else:
            rate = self.rate.mean_rate()
            self.protocol.log.info("Est. rate={rate:.1f}/s at D={difficulty} [{hashrate:0.1f}Ghash/s] for {log_source} [{count} in {elapsed}]", 
                rate=rate, difficulty=difficulty, count=self.rate.count, elapsed=self.rate.elapsed_time(), hashrate=rate*difficulty*(1<<32)/1e9)
        callback(difficulty, rate, **args)


    def _estimate_hashrate(self):
        """Try to estimate the maximum possible hashrate of the worker by setting a high difficulty
           and measuring the rate of shares. If the observed rate is too low, restart with a lower difficulty."""

        def hashrate_callback(difficulty, rate):
            if rate is None or rate <= HASHRATE_ESTIMATION_MINIMUM:
                if difficulty == 1:
                    hashrate_continuation(50e6)     # educated guess; it's probably a CPU miner
                else:
                    # restart with lower difficulty
                    self._rate_estimation(max(1, difficulty//16), hashrate_callback, timeout=HASHRATE_ESTIMATION_TIMEOUT)
            else:
                hashrate_continuation(rate * difficulty * (1 << 32))                

        def hashrate_continuation(h):
            self.log.info("Maximum hashrate found: {hashrate} ({log_source})", hashrate=h)
            self.persistent.set_maximum_hashrate(h)
            self._find_optimal_difficulty()

        self.state = "Estimating hashrate"
        self.log.info("starting maximum hashrate estimation ({log_source})")
        self._rate_estimation(HASHRATE_ESTIMATION_DIFFICULTY, hashrate_callback, timeout=HASHRATE_ESTIMATION_TIMEOUT)


    def _find_optimal_difficulty(self):
        def difficulty_callback(difficulty, rate, best_objective=0, measures={}):
            if rate is None:
                # stop search, difficulty too high, exploit previous results
                difficulty_continuation(measures)
                return
            measures[difficulty] = rate
            hashrate = rate * difficulty * (1 << 32)
            objective = rate * (difficulty**(1/3))
            # stop if we are at 95% of full hashrate and objective function is decreasing
            if hashrate >= 0.95 * self.persistent.maximum_hashrate and objective <= 0.95 * best_objective:
                difficulty_continuation(measures)
                return
            self.log.info("difficulty search: score={objective} @ D={D} (best={best} ({log_source})", objective=objective, D=difficulty, best=best_objective)
            best_objective = max(best_objective, objective)
            self._rate_estimation(difficulty+1, difficulty_callback,
                args={'best_objective': best_objective, 'measures': measures}, timeout=DIFFICULTY_ESTIMATION_TIMEOUT)

        def difficulty_continuation(measures):
            best_objective = 1
            best_difficulty = 1
            for difficulty, rate in measures.items():
                objective = rate * (difficulty**(1/3))
                if objective > best_objective:
                    best_objective = objective
                    best_difficulty = difficulty
            self.log.info("Optimal difficulty: {difficulty}, with objective={objective:.1f} ({log_source})", 
                difficulty=best_difficulty, objective=best_objective)
            self.persistent.set_optimal_difficulty(best_difficulty)
            self._production()

        self.log.info("starting optimal difficulty search ({log_source})")
        self.state = "Finding optimal difficulty"
        self._rate_estimation(1, difficulty_callback, args={'best_objective': 0, 'measures': {}}, timeout=DIFFICULTY_ESTIMATION_TIMEOUT)

    def _production(self):
        self.state = "Production"
        self.log.info("going into production ({log_source}) at difficulty {difficulty}", difficulty=self.persistent.optimal_difficulty)
        self.protocol.set_difficulty(self.persistent.optimal_difficulty)
        self.protocol.notify()
        self.rate = RateMeter()

