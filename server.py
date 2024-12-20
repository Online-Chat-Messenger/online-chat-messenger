import socket
import threading
import time
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

CREATE ="1"
JOIN ="2"

SUCCESS="1"
ERROR="2"

HOST_CLOSE_ROOM="3"
LEAVE="4"
TIMEOUT="5"

class Server:
    def __init__(self,server_address,tcp_port,udp_port,server_private_key,server_public_key):
        self.address=server_address
        self.tcp_port=tcp_port
        self.udp_port=udp_port
        self.udp_socket=None
        self.server_private_key = server_private_key
        self.server_public_key =server_public_key
        self.chat_room={} #{ room名:[ {参加者のtoken : [user name,user_address]}]}
        self.chat_room_password = {} #{room name : password}
        self.room_host_token = {}  # {room_name: host_token}
        self.host_token= 0   #host token
        self.token = 100000 #user token
        self.user_last_active_times={} #{user address:last time}
        self.timeout_interval = 3600 #秒数
        self.keys={} # {user_address:user_public_key}

    #TCP接続でルーム作成、参加を扱う
    def handle_tcp(self):
        tcp_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        tcp_socket.bind((self.address,self.tcp_port))
        tcp_socket.listen()
        while True:
            connection,user_address = tcp_socket.accept()
            self.user_last_active_times[user_address]=time.time()
            threading.Thread(target=self.handle_room, args=(connection, user_address),daemon=True).start()

    def handle_room(self,connection,user_address):
        #payload取得
        operation,room_name,user_name,password,public_key = self.receive_operation(connection)

        self.keys[user_address]=public_key #鍵保存

        if operation ==  CREATE:
            if room_name in self.chat_room:
                state =  ERROR
                payload = "This room name is already used. Use another one."
                #失敗ならエラーメッセージ
            else:
                #成功ならトークンを送信する
                state = SUCCESS
                self.chat_room[room_name] = [] #空リストで初期化
                self.chat_room_password[room_name] = password
                self.chat_room[room_name].append({str(self.host_token):[user_name,user_address]})
                payload = str(self.host_token)
                self.room_host_token[room_name] = str(self.host_token)
                self.host_token+=1
            payload=payload.encode() #バイト列に
            payload_size = len(payload)
            header = state.encode() + payload_size.to_bytes(1,"big")
            connection.sendall(header)
            connection.sendall(payload)
        elif operation==JOIN:
            if room_name not in self.chat_room:
                state =ERROR
                payload = "This room does not exist."
            elif password != self.chat_room_password[room_name]:
                state = ERROR
                payload = "Password is incorrect."
            else:
                state = SUCCESS
                self.chat_room[room_name].append({str(self.token):[user_name,user_address]})
                payload = str(self.token)
                self.token+=1
            payload=payload.encode()
            payload_size = len(payload)
            header = state.encode() + payload_size.to_bytes(1,"big")
            connection.sendall(header)
            connection.sendall(payload)

        server_public_key_size = len(self.server_public_key)
        connection.sendall(server_public_key_size.to_bytes(2,"big")+ self.server_public_key)

    def receive_operation(self,connection):
        try:
            header = connection.recv(5)
            payload_size=int.from_bytes(header,"big")
            payload = connection.recv(payload_size).decode()
            payload_json = json.loads(payload)
            operation = payload_json["operation"]
            room_name = payload_json["room_name"]
            user_name = payload_json["user_name"]
            password  = payload_json["password"]
            public_key_pem = payload_json["public_key"].encode()
            public_key = serialization.load_pem_public_key(public_key_pem)
            return operation,room_name,user_name,password,public_key
        except json.JSONDecodeError:
            pass
        # UDPでメッセージの受信、マルチキャスト送信を行う
    def handle_chat(self):
        # UDPソケット
        self.udp_socket =socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.address, self.udp_port))
        threading.Thread(target=self.check_time, daemon=True).start()
        buffer_size = 4096

        while True:
            # メッセージの受信
            cipher_payload,address = self.udp_socket.recvfrom(buffer_size)

            payload = self.server_private_key.decrypt(
                cipher_payload,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm = hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            data = json.loads(payload)
            room_name = data["room_name"]
            token = data["token"]
            message = data["message"]
            self.user_last_active_times[address]=time.time()

            # ユーザーの退出処理、ホストの場合はルームの削除
            if message == "LEAVE":
                # ホストのトークンを取得
                host_token = self.room_host_token[room_name]
                if token == host_token:
                    self.remove_host(room_name,token)
                else:
                    self.remove_participant(room_name,token)
                #最後にチャットした時間を削除
                del self.user_last_active_times[address]
                continue

            if room_name not in self.chat_room:
                state = ERROR
                operation_payload="This room has been deleted"
                self.udp_socket.sendto(state.encode()+operation_payload.encode(),address)
            else:
                #tokenがあるか確認
                token_found = any(token in user for user in self.chat_room[room_name])
                if token_found:
                    state=SUCCESS
                    receivers = []
                    for participant in self.chat_room[room_name]:
                        exclude_token, user_info = next(iter(participant.items())) #イテレータから最初の要素を取得
                        if exclude_token== token:
                            sender_name = user_info[0]
                        else:
                            receivers.append(user_info[1])
                    for receiver in receivers:
                        receiver_public_key = self.keys[receiver]
                        payload = {
                            "state":SUCCESS,
                            "message":message,
                            "sender_name":sender_name,
                        }
                        payload_bytes = json.dumps(payload).encode()
                        cipher_payload = self.encrypt(receiver_public_key,payload_bytes)

                        #state+sender_name<room_name_tokenなのでbuffer_size超えないはず
                        self.udp_socket.sendto(cipher_payload,receiver)
                else:
                    state = ERROR
                    operation_payload ="You don't have proper token probably because of timeout. First participate in the room."
                    self.udp_socket.sendto(state.encode()+operation_payload.encode(),address)

    def check_time(self):
        while True:
            users_to_delete = []
            current_time = time.time()
            for user_address, last_send_time in self.user_last_active_times.items():
                if current_time - last_send_time >= self.timeout_interval:
                    users_to_delete.append(user_address)
            for user_address in users_to_delete:
                self.remove_user_by_address(user_address)
            time.sleep(self.timeout_interval)

    def remove_user_by_address(self, removed_address):
        room_name,token=self.find_room_and_token_by_address(removed_address)
        if room_name in self.room_host_token:
            host_token = self.room_host_token[room_name]
            if token == host_token:
                self.remove_host(room_name,token,isTimeout=True)
            else:
                self.remove_participant(room_name,token,isTimeout=True)
            del self.user_last_active_times[removed_address]
            del self.keys[removed_address]

    def find_room_and_token_by_address(self, address):
        for room_name, participants in self.chat_room.items():  # すべてのルームを確認
            for user in participants:  # そのルーム内の参加者リストを確認
                for token, user_info in user.items():  # 各参加者のトークンと情報を取得
                    if user_info[1] == address:  # アドレスが一致する場合
                        return room_name, token  # ルーム名とトークンを返す
        return None, None  # 見つからない場合

    # ホストの退出処理
    def remove_host(self,room_name,token,isTimeout=False):
        if isTimeout:
                close_message = "The room has been closed because the host was inactive for a long time."
                payload={
                    "state":TIMEOUT,
                    "message":close_message,
                    "sender_name":"server",
                    "token":token,
                    "this is host" : True
                }
        else:
            close_message = "Room has been closed by the host."
            payload={
                    "state":HOST_CLOSE_ROOM,
                    "message":close_message,
                    "sender_name":"server"
                }

        for participant in self.chat_room[room_name]:
            user_token, user_info = next(iter(participant.items()))
            if token==user_token and not isTimeout:
                continue
            receiver = user_info[1]
            payload_json_bytes=json.dumps(payload).encode()
            cipher_payload = self.encrypt(self.keys[receiver],payload_json_bytes)
            self.udp_socket.sendto(cipher_payload, receiver)

        # ルームデータの削除
        del self.chat_room[room_name]
        del self.chat_room_password[room_name]
        del self.room_host_token[room_name]

    # 参加者の退出処理
    def remove_participant(self,room_name,token,isTimeout=False):
        leaving_user_name = None
        for user in self.chat_room[room_name]:
            user_token, user_info = next(iter(user.items()))
            if user_token == token:
                leaving_user_name = user_info[0]
                address=user_info[1]
                self.chat_room[room_name].remove(user)
                break

        if isTimeout:
            exit_message = f"{leaving_user_name} has left the room because of timeout."
            payload={
                "state":TIMEOUT,
                "message":exit_message,
                "sender_name":"server",
                "token":token,
                "this is host" : False
            }
        else:
            exit_message = f"{leaving_user_name} has left the room."
            payload={
                "state":LEAVE,
                "message":exit_message,
                "sender_name":"server"
            }
        # 他のメンバーに退出通知を送信
        for participant in self.chat_room[room_name]:
            _, user_info = next(iter(participant.items()))
            receiver = user_info[1]

            payload_json_bytes=json.dumps(payload).encode()
            cipher_payload = self.encrypt(self.keys[receiver],payload_json_bytes)
            self.udp_socket.sendto(cipher_payload, receiver)
        #タイムアウトならその人自身にも知らせる
        if isTimeout:
            payload_json_bytes=json.dumps(payload).encode()
            cipher_payload = self.encrypt(self.keys[address],payload_json_bytes)
            self.udp_socket.sendto(cipher_payload, address)

    def encrypt(self,public_key,message):
        cipher_text = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return cipher_text

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key,public_key

if __name__=="__main__":
    server_address="" #すべてのインターフェースで受付
    tcp_port =8000
    udp_port=8001
    server_private_key,server_public_key = generate_rsa_keys()
    server = Server(server_address,tcp_port,udp_port,server_private_key,server_public_key)
    print("running...")
    room=threading.Thread(target = server.handle_tcp)
    chat=threading.Thread(target = server.handle_chat)
    room.start()
    chat.start()
    room.join()
    chat.join()
