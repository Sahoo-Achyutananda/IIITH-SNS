import socket
import sys

if len(sys.argv) != 3:
    print("Usage : python client.py <IP> <PORT>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

round_no = 0

while True:
    opcode = input(">> OPCODE (HELLO/DATA/EXIT) : ").strip()
    payload = input(">> Payload : ").strip()

    msg = f"{opcode}|{round_no}|{payload}"
    client.sendall(msg.encode())

    data = client.recv(1024)
    response = data.decode()
    print("Server: ", response)

    if response.startswith("ERROR"):
        print("Session aborted by server")
        break

    if opcode == "EXIT":
        break

    round_no += 1

client.close()
