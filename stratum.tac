from twisted.application import internet, service
from twisted.web import server
from twisted.python.log import ILogObserver, FileLogObserver
from twisted.python.logfile import DailyLogFile

from twisted_server import StratumFactory, StratumSite, StratumCron

port = 3333

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

# setup logging
logfile = DailyLogFile("my.log", "/mnt/large")
application.setComponent(ILogObserver, FileLogObserver(logfile).emit)

# Connect our MultiService to the application, just like a normal service.
stratumService.setServiceParent(application)