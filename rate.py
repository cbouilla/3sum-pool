import time
import collections

class RateMeter:
    start_time = None
    count = 0
    marks = None
  
    def __init__(self):
        self.marks = collections.deque()

    def _clean(self):
        now = time.time()
        while self.marks and self.marks[0] < now - 60:
            self.marks.popleft()
  
    def mark(self):
        now = time.time()
        if not self.start_time:
            self.start_time = now
        self.count += 1
        self.marks.append(now)
        self._clean()

    def elapsed_time(self):
        now = time.time()
        if not self.start_time:
            return 0
        return now - self.start_time

    def mean_rate(self):
        e = self.elapsed_time()
        if e == 0:
            return 0
        return self.count / e

    def one_minute_rate(self):
        self._clean()
        return len(self.marks) / 60

