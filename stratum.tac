from twisted.application import internet, service
from twisted_server import StratumFactory, StratumSite
from twisted.web import server

port = 9998

# Create a MultiService
stratumService = service.MultiService()

# hook up the stratum server
pool = StratumFactory()
internet.TCPServer(port, pool).setServiceParent(stratumService)

# hook up periodic actions
internet.TimerService(10, pool.wake_clients).setServiceParent(stratumService)

website = server.Site(StratumSite(pool))
internet.TCPServer(8080, website).setServiceParent(stratumService)

# Create an application as normal
application = service.Application("3SUM Stratum Server")

# Connect our MultiService to the application, just like a normal service.
stratumService.setServiceParent(application)