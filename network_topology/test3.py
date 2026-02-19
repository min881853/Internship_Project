#test3.py file
#!/usr/bin/env python
from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, mesh
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference
from mininet.node import OVSController
 
def topology():
    "Create a network."
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
    info("*** Creating nodes\n")
    sta1 = net.addStation('sta1', mac='00:00:00:00:00:11', ip='10.0.0.2/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta2', mac='00:00:00:00:00:12', ip='10.0.0.3/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta3', mac='00:00:00:00:00:13', ip='10.0.0.4/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta4', mac='00:00:00:00:00:14', ip='10.0.0.5/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta5', mac='00:00:00:00:00:15', ip='10.0.0.6/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta6', mac='00:00:00:00:00:16', ip='10.0.0.7/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta7', mac='00:00:00:00:00:17', ip='10.0.0.8/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta8', mac='00:00:00:00:00:18', ip='10.0.0.9/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta9', mac='00:00:00:00:00:19', ip='10.0.0.10/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5)
    net.addStation('sta10', mac='00:00:00:00:00:20', ip='10.0.0.11/8',range=0,
	         	min_x=10, max_x=90, min_y=10, max_y=90, min_v=1, max_v=5) 
    #create Access points
    ap1 = net.addAccessPoint('ap1', ssid='ssid1',mode = 'g',channel=1, position='20,80,0',range=30)
    ap2 = net.addAccessPoint('ap2', ssid='ssid1',mode = 'g',channel=6, position='20,40,0',range=30)
    ap3 = net.addAccessPoint('ap3', ssid='ssid1',mode = 'g',channel=11, position='80,80,0',range=30)
    ap4 = net.addAccessPoint('ap4', ssid='ssid1',mode = 'g',channel=1, position='50,40,0',range=30)
    ap5 = net.addAccessPoint('ap5', ssid='ssid1',mode = 'g',channel=6, position='80,40,0',range=30)
    c0 = net.addController('c0',controller=OVSController, ip='172.20.10.8')  
    info("*** Configuring nodes\n")
    net.configureNodes()
    info("*** Associating Stations\n")
    #links each APs (wired)
    net.addLink(ap1,ap2)
    net.addLink(ap1,ap3)
    net.addLink(ap2,ap4)
    net.addLink(ap3,ap5)
    net.plotGraph(max_x=120,max_y=120)
    net.setMobilityModel(time=5,model='RandomWalk',max_x=100,max_y=100,seed=20)
    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
    ap3.start([c0])
    ap4.start([c0])
    ap5.start([c0])	
    info("*** Running CLI\n")
    CLI(net)
    info("*** Stopping network\n")
    net.stop()  	
if __name__ == '__main__':
    setLogLevel('info')
    topology()









