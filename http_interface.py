import json
from binascii import hexlify, unhexlify

from twisted.internet import reactor, protocol, endpoints
from twisted.protocols import basic
from twisted.logger import Logger
from twisted.web.resource import Resource, NoResource

from persistence import ShareDB

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
        db = ShareDB()
        d['miners'] = self.factory.miner_count
        d['rate'] = db.rate.one_minute_rate()
        d['shares'] = db.n
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
        for proto in self.factory.active_connections:
            worker = proto.worker 
            d = {}
            d['name'] = worker.name
            d['kind'] = worker.kind
            d['total_shares'] = worker.persistent.total_shares
            d['diff1_shares'] = worker.persistent.diff1_shares
            d['state'] = worker.state
            if worker.persistent.maximum_hashrate:
                d['maximum_hashrate'] = worker.persistent.maximum_hashrate
            else:
                d['maximum_hashrate'] = 0
            if worker.persistent.optimal_difficulty:
                d['D'] = worker.persistent.optimal_difficulty
            else:
                d['D'] = '???'
            if worker.rate:
                d['rate'] = "{:.1f}".format(worker.rate.one_minute_rate())
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
        d = {'i': self.i}
        share = ShareDB().get(i)
        d['block_hex'] = hexlify(share.block).decode()
        d['hash']  = hexlify(share.block_hash()).decode()
        d['block_ascii']  = share.block.decode('ascii', errors='replace')
        return b'jsonShareCallback(' + json.dumps(d).encode() + b');'


class ShareDispatch(Resource):
    def getChild(self, name, request):
        try:
            i = int(name)
            if i >= ShareDB().n:    
                raise ValueError
            return ShareView(i)
        except:
            return NoResource()


class  StratumSite(Resource):
    def __init__(self, factory):
        super(StratumSite, self).__init__()
        self.factory = factory

    def getChild(self, name, request):
        if name == b'navbar':
            return NavBarStats(self.factory)
        elif name == b'workers':
            return  WorkerStats(self.factory)
        elif name == b'share':
            return  ShareDispatch()
        else:
            return NoResource()

