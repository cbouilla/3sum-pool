from twisted.application import internet, service
from twisted_server import StratumFactory

port = 9998

# Create a MultiService, and hook up a TCPServer and a UDPServer to it as
# children.
stratumService = service.MultiService()
tcpFactory = StratumFactory()
internet.TCPServer(port, tcpFactory).setServiceParent(stratumService)

internet.TimerService(10, tcpFactory.wake_clients).setServiceParent(stratumService)

# Create an application as normal
application = service.Application("3SUM Stratum Server")

# Connect our MultiService to the application, just like a normal service.
stratumService.setServiceParent(application)