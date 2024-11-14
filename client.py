import socket

def main():
    host_room = {}
    join_room = {}
    try:
        server_address="localhost"
        server_port=9000
        #TCPでリクエスト送信
        tcp_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        tcp_socket.connect((server_address,server_port))
        #1でルーム作成
        print("Which operation do you want to do")
        print("1: Create a chat room")
        print("2: Join a chat room")
        operation=input(">")
        while operation !="1" and operation !="2":
            print("Invalid operation. Enter 1 or 2")
            operation = input(">")
        #room name 入力
        room_name = input("Enter room name: ")
        room_name_size = len(room_name.encode())
        #room name が256バイト以下か確認
        if room_name_size > 2**8:
            print("Room name must not be over 256 bytes")
            print("FYI: This room name has "+ room_name_size + "bytes")
            room_name = input("Re-enter room name: ")
            room_name_size = len(room_name.encode())
        #user name 入力
        user_name = input("Enter user name: ")
        state="0"
        operation_payload=user_name
        operation_payload_size=len(operation_payload.encode())
        header = room_name_size.to_bytes(1,"big") + operation.encode() + state.encode() + operation_payload_size.to_bytes(29,"big")
        tcp_socket.sendall(header)
        tcp_socket.sendall(room_name.encode()+operation_payload.encode())

        if operation == "1":
            header = tcp_socket.recv(30)
            status = header[:1].decode()
            operation_payload_size = int.from_bytes(header[1:],"big")
            operation_payload = tcp_socket.recv(operation_payload_size)
            host_token = operation_payload.decode()
            host_room[room_name] = host_token

        elif operation == "2":
            status=tcp_socket.recv(5).decode()
            if status =="error":
                print("this room does not exist.")
            else:
                operation_payload_size_bytes = tcp_socket.recv(29)
                operation_payload_size=int.from_bytes(operation_payload_size_bytes,"big")
                operation_payload = tcp_socket.recv(1)
                token = operation_payload.decode()
                join_room[room_name] = token
                tcp_socket.close()


        #2でルーム参加
    except Exception as e:
        print(e)
        print("Connection Failed.")
main()
