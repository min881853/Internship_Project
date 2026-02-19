#testbed.py file
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
import os

def move_station(net, station, x, y):
    station.setPosition(f"{x},{y},0")
    print(station.position)

def topology():
    "Create a network."
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
    volume_path = "/home/wifi/containernet/containernet/volumes"
    file_path = f"{volume_path}/test1.txt"  
    last_modified_time = None  
        
    info("*** Adding docker container\n")
    attacker1 = net.addStation(
        'attacker1', cls=DockerSta, dimage="nisach/ddos_attack:v3.1", mac='00:00:00:00:00:11',
        ip='10.0.0.11/8', range=30, mem_limit='512m', cpu_shares=10, position='10,10,0',volumes=[f"{volume_path}:/mnt/volumes"])
    attacker2 = net.addStation(
        'attacker2', cls=DockerSta, dimage="nisach/ddos_attack:v3.1", mac='00:00:00:00:00:12',
        ip='10.0.0.12/8', range=30, mem_limit='512m', cpu_shares=10, position='30,10,0',volumes=[f"{volume_path}:/mnt/volumes"])
    attacker3 = net.addStation(
        'attacker3', cls=DockerSta, dimage="nisach/ddos_attack:v3.1", mac='00:00:00:00:00:16',
        ip='10.0.0.13/8', range=30, mem_limit='512m', cpu_shares=10, position='0,0,0',volumes=[f"{volume_path}:/mnt/volumes"])
    server1 = net.addStation(
        'server1', cls=DockerSta, dimage="knotnot/proxy-server:v.2.2.1", mac='00:00:00:00:00:13',
        ip='10.0.0.4/8', range=30, mem_limit='512m', cpu_shares=30, position='40,80,0',volumes=[f"{volume_path}:/mnt/volumes"])
    server2 = net.addStation(
        'server2', cls=DockerSta, dimage="knotnot/backend-1:v.2.2.1", mac='00:00:00:00:00:14',
        ip='10.0.0.5/8', range=30, mem_limit='512m', cpu_shares=20, position='25,80,0',volumes=[f"{volume_path}:/mnt/volumes"])
    server3 = net.addStation(
        'server3', cls=DockerSta, dimage="knotnot/backend-1:v.2.2.1", mac='00:00:00:00:00:15',
        ip='10.0.0.6/8', range=30, mem_limit='512m', cpu_shares=20, position='30,80,0',volumes=[f"{volume_path}:/mnt/volumes"])
 
    user1 = net.addStation(
        'user1', cls=DockerSta, dimage="nisach/ddos_attack:v3", mac='00:00:00:00:00:51',
        ip='10.0.0.51/8', range=30, mem_limit='512m', cpu_shares=5, position='50,30,0',volumes=[f"{volume_path}:/mnt/volumes"])
    user2 = net.addStation(
        'user2', cls=DockerSta, dimage="nisach/ddos_attack:v3", mac='00:00:00:00:00:52',
        ip='10.0.0.52/8', range=30, mem_limit='512m', cpu_shares=5, position='10,30,0',volumes=[f"{volume_path}:/mnt/volumes"])
        
    ap1 = net.addAccessPoint('ap1', ssid='ssid1', mode='g', channel=1, position='30,30,0', range=30)
    ap2 = net.addAccessPoint('ap2', ssid='ssid1', mode='g', channel=1, position='30,80,0', range=30)
    c0 = net.addController('c0', controller=RemoteController,ip='172.20.10.8')

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
    while True:
        modified_time = os.path.getmtime(file_path)
        if last_modified_time is None or modified_time > last_modified_time:
            last_modified_time = modified_time
            with open(file_path, "r") as f:
                command = f.readline().strip()
                if command:
                    print(f" Executing command: {command} \n")
                    parts = command.split()
                    if len(parts) == 4 and parts[0] == "move":
                        station_name = parts[1]
                        valid_stations = {'a1': attacker1, 'a2': attacker2, 'a3': attacker3, 's1': server1, 's2': server2, 's3': server3,'u1':user1,'u2':user2}
                        if station_name in valid_stations:
                            station = valid_stations[station_name]
                            try:
                                x, y = float(parts[2]), float(parts[3])
                                move_station(net, station, x, y)
                                net.plotGraph(max_x=100,max_y=100)
                                plt.pause(0.1) 
                            except ValueError:
                                print("Invalid value\n")

        plt.pause(0.1)
        time.sleep(1)

    info("*** Running CLI\n")
    CLI(net)
    info("*** Stopping network\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    topology()

