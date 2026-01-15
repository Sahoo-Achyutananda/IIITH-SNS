import socket
from protocol_fsm import ProtocolError, ProtocolFSM

import sys

if len(sys.argv) != 3:
    print("Usage : python server.py <IP> <PORT>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = int(sys.argv[2])

def parse_message(raw : str) -> dict:

    parts = raw.split("|", 2)
    if(len(parts) != 3):
        raise ValueError("Incorrect Message Format")
    
    opcode, round_str, payload = raw.split("|", 2)

    return {
        "opcode" : opcode,
        "round" : int(round_str),
        "payload" : payload
    }


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Server listening...")

conn, addr = server.accept()
print("Connected to", addr)

fsm = ProtocolFSM()

def terminate(reason):
    print("Session terminated:", reason)
    conn.sendall(f"ERROR|{reason}".encode())
    conn.close()
    exit()

while True:
    data = conn.recv(1024)
    if not data:
        break

    raw_msg = data.decode()
    print("Received:", raw_msg)

    try:
        message = parse_message(raw_msg) # this returns a dict
        response = fsm.process(message) # this changes the state of the FSM and returns a response
        conn.sendall(response.encode()) # response is sent to the client

        if response == "SESSION_TERMINATED":
            terminate("Session Terminated Cleanly")

    except (ValueError, ProtocolError) as e:
        error_msg = f"ERROR:{str(e)}"
        terminate(error_msg)
        break

conn.close()
server.close()
