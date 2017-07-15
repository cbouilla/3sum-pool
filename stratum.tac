from twisted.application import internet, service
from twisted.web import server
from twisted_server import StratumFactory, StratumSite, StratumCron

port = 9998

# Create a MultiService
stratumService = service.MultiService()

# hook up the stratum server
pool = StratumFactory()
internet.TCPServer(port, pool).setServiceParent(stratumService)

# hook-up the JSONP webservice
website = server.Site(StratumSite(pool))
internet.TCPServer(8080, website).setServiceParent(stratumService)

# hook up periodic actions
cron = StratumCron(pool)
internet.TimerService(60, cron.minute).setServiceParent(stratumService)

# Create an application as normal
application = service.Application("3SUM Stratum Server")

# Connect our MultiService to the application, just like a normal service.
stratumService.setServiceParent(application)