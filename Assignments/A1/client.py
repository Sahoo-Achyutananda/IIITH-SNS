import socket

HOST = "127.0.0.1"
PORT = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

round_no = 0

while True:
    opcode = input(">> OPCODE (HELLO/DATA/EXIT) : ")
    payload = input(">> Payload : ")

    msg = f"{opcode}|{round_no}|{payload}"
    client.sendall(msg.encode())

    data = client.recv(1024)
    print("Server: ", data.decode())

    if opcode == "EXIT":
        break

    round_no += 1

client.close()
