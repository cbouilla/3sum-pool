from twisted.application import internet, service
from twisted.web import server
from twisted.python.log import ILogObserver, FileLogObserver
from twisted.python.logfile import LogFile
from twisted.logger import LogLevelFilterPredicate, FilteringLogObserver, textFileLogObserver, LogLevel

from protocol import StratumFactory
from http_interface import StratumSite
from persistence import ACCESS_LOG, STRATUM_LOG, db_cron_hourly

port = 3333

# Create a MultiService
stratumService = service.MultiService()

# hook up the stratum server
pool = StratumFactory()
internet.TCPServer(port, pool).setServiceParent(stratumService)


# hook-up the JSONP webservice
website = server.Site(StratumSite(pool), logPath=ACCESS_LOG)
internet.TCPServer(8080, website).setServiceParent(stratumService)

# hook up periodic actions
## ping workers
internet.TimerService(30, pool.ping).setServiceParent(stratumService)
# flush DB
internet.TimerService(3600, db_cron_hourly).setServiceParent(stratumService)
# re-notify
internet.TimerService(3600, pool.rotate_job).setServiceParent(stratumService)


# Create an application as normal
application = service.Application("3SUM Stratum Server")

# setup logging. TODO : separate access.log vs stratum.log
loglevel = LogLevel.levelWithName('info')
predicate = LogLevelFilterPredicate()
predicate.setLogLevelForNamespace("", loglevel)
filtering_logger = FilteringLogObserver(textFileLogObserver(open(STRATUM_LOG, 'a')), [predicate])
application.setComponent(ILogObserver, filtering_logger)


# Connect our MultiService to the application, just like a normal service.
stratumService.setServiceParent(application)