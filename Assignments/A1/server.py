import socket

HOST = "127.0.0.1"
PORT = 5000

"""
socket.socket() is the constructor for the socket class, located inside the socket module.
In Python, it is very common for a module to have the exact same name as the primary class it contains.
When we type import socket, we are importing the module (a file named socket.py). Inside that file, there is a class also named socket.
"""

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST,PORT))
server.listen(1)

print("Server sunn rha hai ... apne pyaar ka intezaar kar rha hai")

conn, addr = server.accept()
print("Connected to", addr)

"""
Even though your main server socket (the one we named server) is listening, it does not actually talk to the client.
Instead, .accept() spawns a brand new socket specifically for that one client.
The Original Socket (server): Stays at the "front door," continuing to listen for new people.
The New Socket (conn): Goes into a "private room" to handle the actual conversation (sending and receiving data) with that specific client.
"""

while True:
    data = conn.recv(1024) # we specify the amount of data to recieve
    # like c++, .recv() is also blocking, it remains in this line until client sends some data
    if not data:
        print("Client disconnected")
        break

    msg = data.decode()
    print("Client says:", msg)

    response  = "ACK : " + msg
    conn.sendall(response.encode())

conn.close()
server.close()

"""
1. Why encode and decode ?
.encode(): Converts a String (human-readable) into Bytes (machine-readable).  
.decode(): Converts Bytes back into a String.  
The Rule: You Encode before you send(), and you Decode after you recv().

2. send vs sendall()
In socket programming, the primary difference is that send() may send only a portion of the data you provide, 
requiring you to handle subsequent sends, while sendall() guarantees that all data is sent or it raises an exception. 
"""