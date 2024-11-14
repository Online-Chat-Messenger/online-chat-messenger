import socket
import threading

chat_room={}
user_host_token = {}
user_token = {}
user_addresses ={}
host_token= 0

def main():

    token=0
    server_address=""
    tcp_port=9000
    udp_port=9001

    tcp_thread = threading.Thread(target=handle_room,args=(server_address,tcp_port))
    udp_thread = threading.Thread(target=handler_chat,args=(server_address,udp_port))
    tcp_thread.start()


#TCP接続でルーム作成、接続を扱う
def handle_room(server_address,tcp_port):
    tcp_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    tcp_socket.bind((server_address,tcp_port))
    tcp_socket.listen()
    while True:
        connection,address = tcp_socket.accept()
        #header
        header = connection.recv(32)
        room_name_size = int.from_bytes(header[:1],"big")
        operation = header[1:2].decode()
        state = header[2:3].decode()
        operation_payload_size = int.from_bytes(header[3:],"big")
        print(room_name_size)
        print(operation)
        print(state)
        print(operation_payload_size)

        body = connection.recv(room_name_size+operation_payload_size)
        room_name = body[:room_name_size].decode()
        operation_payload = body[room_name_size:].decode()

        print(room_name)
        print(operation_payload)

        if operation == "1":
            state = "1"
            user_name = operation_payload
            if room_name not in chat_room:
                chat_room[room_name] = []
            chat_room[room_name].append(str(host_token))
            user_host_token[str(host_token)]= user_name
            user_addresses[str(host_token)] = address
            operation_payload = str(host_token)
            operation_payload_size = len(operation_payload.encode())
            header = state.encode() + operation_payload_size.to_bytes(29,"big")
            connection.sendall(header)
            connection.sendall(operation_payload.encode())
            print(chat_room)
            print(user_host_token)
            host_token+=1

        elif operation=="2":
            user_name = operation_payload
            print(chat_room)
            if room_name not in chat_room:
                state ="error"
                connection.sendall(state.encode())
            else:
                operation_payload = str(token)
                operation_payload_size = len(operation_payload.encode())
                connection.sendall(operation_payload_size.to_bytes(29,"big"))
                connection.sendall(operation_payload.encode())
                token+=1

# UDPでメッセージの受信、マルチキャスト送信を行う
def handler_chat(server_address,udp_port):
    buffer_size = 4096
    room_name_size_buffer = 1
    token_size_buffer = 1
    header_size = room_name_size_buffer + token_size_buffer
    udp_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    udp_socket.bind((server_address,udp_port))
    while True:
        data,address = udp_socket.recv(buffer_size)
        header = data[:header_size]
        room_name_size = header[:room_name_size_buffer]
        token_size = header[room_name_size_buffer:room_name_size_buffer+token_size_buffer]
        body = data[header_size:]
        room_name = body[:room_name_size]
        token_name = body[room_name_size:room_name_size+token_size]
        message = body[room_name_size+token_size:]


if __name__=="__main__":
    main()
