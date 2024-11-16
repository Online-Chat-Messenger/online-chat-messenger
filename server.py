import socket
import threading
import time



class Server:
    def __init__(self):
        self.chat_room={} #{ room名:[ {参加者のtoken : [user name,user_address]} ] }
        self.user_host_token = {} #host token : user name
        self.host_token= 0
        self.address=""
        self.tcp_port =9000
        self.udp_port=9001
        self.token = 1000
        self.user_last_chat_times={}
        self.buffer_size = 4096
        self.timeout_interval = 600 #秒数

    def run(self):
        threading.Thread(target = self.handle_room).start()
        threading.Thread(target = self.handle_chat).start()

    #TCP接続でルーム作成、接続を扱う
    def handle_room(self):
        tcp_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        tcp_socket.bind((self.address,self.tcp_port))
        tcp_socket.listen()
        while True:
            connection,user_address = tcp_socket.accept()
            #header
            header = connection.recv(32)
            room_name_size = int.from_bytes(header[:1],"big")
            operation = header[1:2].decode()
            state = header[2:3].decode()
            operation_payload_size = int.from_bytes(header[3:],"big")

            body = connection.recv(room_name_size+operation_payload_size)
            room_name = body[:room_name_size].decode()
            operation_payload = body[room_name_size:].decode()
            print("operation", operation)
            print("room name",room_name)
            print("payload",operation_payload)

            if operation == "1":
                user_name = operation_payload
                if room_name  in self.chat_room:
                    state =  "2"
                    operation_payload = "This room name is already used. Use another one."
                    operation_payload_size=len(operation_payload.encode())
                else:
                    state = "1"
                    self.chat_room[room_name] = []
                    self.chat_room[room_name].append({str(self.host_token):[user_name,user_address]})
                    self.user_host_token[str(self.host_token)]= [user_name,user_address]
                    operation_payload = str(self.host_token)
                    self.host_token+=1
                operation_payload_size = len(operation_payload.encode())
                header = state.encode() + operation_payload_size.to_bytes(29,"big")
                connection.sendall(header)
                connection.sendall(operation_payload.encode())
                print(self.chat_room)

            elif operation=="2":
                user_name = operation_payload
                print("追加前",self.chat_room)
                if room_name not in self.chat_room:
                    state ="2"
                    operation_payload = "This room does not exist."
                else:
                    state = "1"
                    self.chat_room[room_name].append({str(self.token):[user_name,user_address]})
                    operation_payload = str(self.token)
                    self.token+=1
                operation_payload_size = len(operation_payload.encode())
                header = state.encode() + operation_payload_size.to_bytes(29,"big")
                connection.sendall(header)
                connection.sendall(operation_payload.encode())
                print("追加後",self.chat_room)


    # UDPでメッセージの受信、マルチキャスト送信を行う
    def handle_chat(self):
        # UDPソケット
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((self.address, self.udp_port))

        room_name_size_buffer = 1
        token_size_buffer = 1
        header_size = room_name_size_buffer + token_size_buffer

        print('\nwaiting to receive message')

        threading.Thread(target=self.check_time, daemon=True).start()

        while True:
            # メッセージの受信
            data,address = udp_socket.recvfrom(self.buffer_size)
            header = data[:header_size]
            room_name_size = int.from_bytes(header[:room_name_size_buffer],"big")
            token_size = int.from_bytes(header[room_name_size_buffer:room_name_size_buffer+token_size_buffer],"big")
            body = data[header_size:]
            room_name = body[:room_name_size].decode()
            token = body[room_name_size:room_name_size+token_size].decode()
            message = body[room_name_size+token_size:].decode()

            if room_name not in self.chat_room:
                state = "2"
                udp_socket.sendto(state.encode(),address)
            else:
                self.chat_room[room_name]
                token_found = any(token in user for user in self.chat_room[room_name])
                if token_found:
                    state="1"
                    print("message",message)
                    receivers = []
                    for participant in self.chat_room[room_name]:
                        exclude_token, user_info = next(iter(participant.items()))
                        if exclude_token== token:
                            sender_name = user_info[0]
                        else:
                            receivers.append(user_info[1])
                    for receiver in receivers:
                        #このままじゃpacket_size超える可能性ある
                        user_name_size = len(sender_name.encode())
                        udp_socket.sendto(user_name_size.to_bytes(1,"big")+(sender_name+message).encode(),receiver)
                else:
                    state = "2"
                    mes ="You don't have proper token probably because of timeout. First participate in the room."
                    udp_socket.sendto(state.encode(),address)

    def check_time(self):
        while True:
            users_to_delete = []
            current_time = time.time()
            for user, last_send_time in self.user_last_chat_times.items():
                if current_time - last_send_time >= self.timeout_interval:
                    users_to_delete.append(user)
            for user in users_to_delete:
                del self.user_last_chat_times[user]
            time.sleep(self.timeout_interval)


if __name__=="__main__":
    server = Server()
    server.run()