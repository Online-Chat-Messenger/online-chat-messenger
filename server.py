import socket
import threading
import time
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend



class Server:
    def __init__(self):
        self.chat_room={} #{ room名:[ {参加者のtoken : [user name,user_address]}]}
        self.chat_room_password = {} #{room name : password}
        self.user_host_token = {} #host token : user name
        self.room_host_token = {}  # {room_name: host_token}  # ここを追加
        self.host_token= 0
        self.address=""
        self.tcp_port =9000
        self.udp_port=9001
        self.token = 1000
        self.user_last_chat_times={}
        self.buffer_size = 4096
        self.timeout_interval = 600 #秒数
        self.server_public_key, self.server_private_key = self.generate_rsa_keys()
        self.key={}

    def run(self):
        threading.Thread(target = self.handle_room).start()
        threading.Thread(target = self.handle_chat).start()

    def generate_rsa_keys(self):

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        public_key = private_key.public_key()

        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key, private_key

    #TCP接続でルーム作成、接続を扱う
    def handle_room(self):
        tcp_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        tcp_socket.bind((self.address,self.tcp_port))
        tcp_socket.listen()
        while True:
            connection,user_address = tcp_socket.accept()
            #header
            #header = connection.recv(32)
            header_size = connection.recv(1)
            print(header_size)
            header = connection.recv(int.from_bytes(header_size,"big"))
            print(header.decode())
            header = json.loads(header.decode())
            operation = header["operation"]
            state = header["state"]
            operation_payload_size = header["operation_payload_size"]
            #room_name_size = int.from_bytes(header[:1],"big")
            #operation = header[1:2].decode()
            #state = header[2:3].decode()
            #public_key_size = int.from_bytes(header[3:8],"big")
            #operation_payload_size = int.from_bytes(header[3:],"big")
            body = connection.recv(operation_payload_size)
            #public_key = body[room_name_size:room_name_size+public_key_size]
            operation_payload = body.decode()
            payload_data = json.loads(operation_payload)
            room_name = payload_data["room_name"]
            public_key = payload_data["public_key"].encode()
            public_key = serialization.load_pem_public_key(public_key)
            self.key[user_address]=public_key
            password = payload_data["password"]
            #print("operation", operation)
            print("room name",room_name)
            #print("payload",payload_data)

            if operation == "1":
                user_name = payload_data["user_name"]
                if room_name  in self.chat_room:
                    state =  "2"
                    operation_payload = "This room name is already used. Use another one."
                    operation_payload_size=len(operation_payload.encode())
                else:
                    state = "1"
                    self.chat_room[room_name] = []
                    self.chat_room_password[room_name] = password
                    self.chat_room[room_name].append({str(self.host_token):[user_name,user_address]})
                    self.user_host_token[str(self.host_token)]= [user_name,user_address]
                    operation_payload = str(self.host_token)
                    self.room_host_token[room_name] = str(self.host_token)
                    self.host_token+=1
                operation_payload_size = len(operation_payload.encode())
                header = state.encode() + operation_payload_size.to_bytes(29,"big")
                connection.sendall(header)
                connection.sendall(operation_payload.encode())
                print(self.chat_room)

            elif operation=="2":
                #passwordが合っている場合
                user_name = payload_data["user_name"]
                print("追加前",self.chat_room)
                if room_name not in self.chat_room:
                    state ="2"
                    operation_payload = "This room does not exist."
                elif password != self.chat_room_password[room_name]:
                    state = "2"
                    operation_payload = "Password is incorrect."
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

            
            connection.sendall(self.server_public_key)


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

            message = body[room_name_size+token_size:]
            # print(message)
            plain_text = self.server_private_key.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            

            
            # ユーザーの退出処理、ホストの場合はルームの削除
            if plain_text.decode() == "EXIT":   
                # ホストのトークンを取得
                host_token = self.room_host_token.get(room_name)

                if host_token is None:
                    # ホストトークンが見つからない場合の処理
                    print(f"Host token not found for room: {room_name}")
                else:
                    if token == host_token:
                        # ホストが退出する場合
                        close_message = "Room has been closed by the host."
                        state = "2"
                        sender_name = "server"
                        user_name_size = len(sender_name.encode())
                        for participant in self.chat_room[room_name]:
                            _, user_info = next(iter(participant.items()))
                            receiver = user_info[1]
                            cipher_close_message = self.server_encrypt(self.key[receiver],close_message.encode())
                            udp_socket.sendto(user_name_size.to_bytes(1,"big")+(sender_name).encode()+cipher_close_message, receiver)

                        # ルームデータの削除
                        del self.chat_room[room_name]
                        del self.chat_room_password[room_name]
                        del self.user_host_token[host_token]
                        del self.room_host_token[room_name]  # 追加
                    else:
                        # 通常ユーザーの退出処理
                        leaving_user_name = None
                        for user in self.chat_room[room_name]:
                            user_token, user_info = next(iter(user.items()))
                            if user_token == token:
                                leaving_user_name = user_info[0]
                                self.chat_room[room_name].remove(user)
                                break

                        # 他のメンバーに退出通知を送信
                        exit_message = f"{leaving_user_name} has left the room."
                        sender_name = "server"
                        user_name_size = len(sender_name.encode())
                        for participant in self.chat_room[room_name]:
                            _, user_info = next(iter(participant.items()))
                            receiver = user_info[1]
                            cipher_exit_message = self.server_encrypt(self.key[receiver],exit_message.encode())
                            udp_socket.sendto(user_name_size.to_bytes(1,"big")+(sender_name).encode()+cipher_exit_message, receiver)

                        # ルームにメンバーがいなくなった場合、ルームを削除
                        if len(self.chat_room[room_name]) == 0:
                            del self.chat_room[room_name]
                            del self.chat_room_password[room_name]
                            del self.room_host_token[room_name]  # 追加

                continue
            # ここまでユーザーの退出処理


            if room_name not in self.chat_room:
                state = "2"
                udp_socket.sendto(state.encode(),address)
            else:
                self.chat_room[room_name]
                token_found = any(token in user for user in self.chat_room[room_name])
                if token_found:
                    state="1"
                    print("message",plain_text)
                    receivers = []
                    for participant in self.chat_room[room_name]:
                        exclude_token, user_info = next(iter(participant.items()))
                        if exclude_token== token:
                            sender_name = user_info[0]
                        else:
                            receivers.append(user_info[1])
                    for receiver in receivers:
                        # self.keysから公開鍵を入手
                        receiver_public_key = self.key[receiver]
                        # 公開鍵で暗号化
                        cipher_text = receiver_public_key.encrypt(
                            plain_text,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        #このままじゃpacket_size超える可能性ある
                        user_name_size = len(sender_name.encode())
                        udp_socket.sendto(user_name_size.to_bytes(1,"big")+(sender_name).encode()+cipher_text,receiver)
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

    def server_encrypt(self,public_key,message):
        cipher_text = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return cipher_text


if __name__=="__main__":
    server = Server()
    server.run()