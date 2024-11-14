import socket
import threading

packet_size = 4096


def main():
    # UDPソケット
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = input("\nType in the server's address to connect to: ")
    server_port = 9001

    # ユーザー名入力
    user_name = input("Set a user name: ")
    user_name_bytes = user_name.encode()

    # ユーザー名が長すぎる場合のチェック
    while len(user_name_bytes) > 255:
        print("User name is too long. Must not be over 255 bytes.")
        user_name = input("Reset a user name: ")
    user_name_size = len(user_name.encode())
    available_message_size=packet_size-user_name_size

    receive_thread = threading.Thread(target=receive, args=(sock,))
    receive_thread.daemon=True
    receive_thread.start()
    while True:
        # Enter message
        message = input("Enter message you want to send: ")
        message_size=len(message.encode())
        while message_size>available_message_size:
            message = input("Too long. Re-Enter message you want to send: ")
            message_size=len(message.encode())
        sock.sendto(user_name_size.to_bytes(1, "big")+(user_name+message).encode(),(server_address,server_port))

def receive(sock):
    while True:
        packet, sender = sock.recvfrom(packet_size)
        user_name_size = packet[0]
        user_name = packet[1:user_name_size+1].decode()
        message = packet[user_name_size+1:].decode()
        print("\n"+user_name+": "+message)

if __name__ == "__main__":
    main()
