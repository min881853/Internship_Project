#test4.py file
#!/usr/bin/env python
from mininet.log import setLogLevel, info
from containernet.net import Containernet
from containernet.cli import CLI
from containernet.node import DockerSta
from mininet.node import RemoteController, OVSController
from containernet.term import makeTerm
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference
from mn_wifi.link import wmediumd, mesh
from mininet.link import TCLink

import matplotlib.pyplot as plt
import time 


def move_station(net, station, x, y):
    station.setPosition(f"{x},{y},0")  # set new station's position
    net.plotGraph(max_x=100, max_y=100)  # Update the graph

def topology():
    "Create a network."
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference) 
        
    info("*** Adding docker container\n")
    attacker1 = net.addStation(
        'attacker1', cls=DockerSta, dimage="nisach/ddos_attack:v4", mac='00:00:00:00:00:11',
        ip='10.0.0.11/8', range=30, mem_limit='512m', cpu_shares=10, position='10,10,0')
    attacker2 = net.addStation(
        'attacker2', cls=DockerSta, dimage="nisach/ddos_attack:v4", mac='00:00:00:00:00:12',
        ip='10.0.0.12/8', range=30, mem_limit='512m', cpu_shares=10, position='30,10,0')
    attacker3 = net.addStation(
        'attacker3', cls=DockerSta, dimage="nisach/ddos_attack:v4", mac='00:00:00:00:00:16',
        ip='10.0.0.13/8', range=30, mem_limit='512m', cpu_shares=10, position='0,0,0')
    server1 = net.addStation(
        'server1', cls=DockerSta, dimage="knotnot/proxy-server:v.2.2.1", mac='00:00:00:00:00:13',
        ip='10.0.0.4/8', range=30, mem_limit='512m', cpu_shares=30, position='40,80,0')
    server2 = net.addStation(
        'server2', cls=DockerSta, dimage="knotnot/backend-1:v.2.2.1", mac='00:00:00:00:00:14',
        ip='10.0.0.5/8', range=30, mem_limit='512m', cpu_shares=20, position='25,80,0')
    server3 = net.addStation(
        'server3', cls=DockerSta, dimage="knotnot/backend-1:v.2.2.1", mac='00:00:00:00:00:15',
        ip='10.0.0.6/8', range=30, mem_limit='512m', cpu_shares=20, position='30,80,0')
    
    user1 = net.addStation(
        'user1', cls=DockerSta, dimage="ubuntu:trusty", mac='00:00:00:00:00:51',
        ip='10.0.0.6/51', range=30, mem_limit='512m', cpu_shares=5, position='50,30,0')
    user2 = net.addStation(
        'user2', cls=DockerSta, dimage="ubuntu:trusty", mac='00:00:00:00:00:52',
        ip='10.0.0.6/51', range=30, mem_limit='512m', cpu_shares=5, position='10,30,0')

    ap1 = net.addAccessPoint('ap1', ssid='ssid1', mode='g', channel=1, position='30,30,0', range=30)
    ap2 = net.addAccessPoint('ap2', ssid='ssid1', mode='g', channel=1, position='30,80,0', range=30)
    c0 = net.addController('c0', controller=RemoteController,ip='127.0.0.1', port = 6653)
    #c0 = net.addController('c0', controller=OVSController)


    info("*** Configuring nodes\n")
    net.configureWifiNodes()
    net.setPropagationModel(model="logDistance", exp=5)
    net.addLink(ap1, ap2)
    net.plotGraph(max_x=100, max_y=100)
    

    info("*** Starting network\n")
    net.build()
    c0.start()
    ap1.start([c0])
    ap2.start([c0])
        
    # Define a custom CLI to add the move features
    class CustomCLI(CLI):
        
        def do_move(self, line):
            args = line.split()
            if len(args) != 3:
                print("Usage: move <station_name> <x> <y>")
                return
            station_name, x, y = args[0], args[1], args[2]
            try:
                x = float(x) 
                y = float(y)
                valid_station = {
                    'a1': attacker1,
                    'a2': attacker2,
                    'a3': attacker3,
                    's1': server1,
                    's2': server2,
                    's3': server3,
                    'u1': user1,
                    'u2': user2
                }
           	
           	#****** Set rules for attacker's moving**************************************
                if x < 0 or x > 100: 
                    print("x is over boundary!. Try again!")
                if y < 0 or y > 100: 
                    print("y is over boundary!. Try again!")
                #****************************************************************************
                if station_name not in valid_station:
                    print(f"Error: Unknown station {station_name}")
                    return
                station = valid_station[station_name]
                move_station(net, station, x, y)  
            except ValueError:
                print("Invalid coordinates!")

    
    info("*** Running CLI\n")
    CustomCLI(net)  # Use CustomCLI to add move 

    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology() 

