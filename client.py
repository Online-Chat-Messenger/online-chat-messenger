import socket
import threading
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import sys

CREATE ="1"
JOIN ="2"

ERROR="2"
SUCCESS="1"

class Client:
    def __init__(self,server_address,server_tcp_port,server_udp_port,public_key,private_key):
        self.server_address=server_address
        self.server_tcp_port=server_tcp_port
        self.server_udp_port=server_udp_port
        self.server_public_key = None
        self.public_key = public_key
        self.private_key = private_key

    def run(self):
        while True:
            #TCPでリクエスト送信
            tcp_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            tcp_socket.connect((self.server_address,self.server_tcp_port))
            _, local_port = tcp_socket.getsockname()  # 現在のポート番号をudpでも使うためのもの
            #1でルーム作成 2で参加 3でプログラム終了
            operation = self.input_operation()

            #room name,user name,password 入力
            room_name,user_name,password= self.input_info()

            payload = {"operation":operation,"room_name":room_name,"user_name":user_name,"password":password,"public_key":self.public_key.decode()}
            payload_bytes = json.dumps(payload).encode()
            payload_size=len(payload_bytes)
            header = payload_size.to_bytes(5,"big")
            tcp_socket.sendall(header+payload_bytes)

            if operation == CREATE:
                header = tcp_socket.recv(2)
                state = header[:1].decode()
                payload_size = int.from_bytes(header[1:2],"big")
                payload = tcp_socket.recv(payload_size).decode()
                if state ==SUCCESS:
                    token = payload
                    print("successfully created")
                elif state ==ERROR:
                    print(payload)

            elif operation == JOIN:
                header = tcp_socket.recv(2)
                state = header[:1].decode()
                payload_size=int.from_bytes(header[1:2],"big")
                payload = tcp_socket.recv(payload_size).decode()
                if state =="2":
                    print(payload)
                    continue #最初から
                else:
                    token = payload

            server_public_key_size = int.from_bytes(tcp_socket.recv(2),"big")
            server_public_key_pem = tcp_socket.recv(server_public_key_size)
            self.server_public_key = serialization.load_pem_public_key(server_public_key_pem)
            tcp_socket.close()

            #UDPでメッセージ送信処理
            self.send_message(room_name,token,local_port)

    def send_message(self,room_name,token,local_port):

        # UDPソケット
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind(("",local_port))

        receive_thread = threading.Thread(target=self.receive, args=(udp_socket,),daemon=True)
        receive_thread.start()

        while True:
            #Enter message
            cipher_payload,exit_flag = self.input_message(token,room_name)
            #Return cipher_payload comprised of cipher_message,room name,token
            udp_socket.sendto(cipher_payload,(self.server_address,self.server_udp_port))

            # 受取スレッドが終了したら終了
            if(receive_thread.is_alive() == False):
                break
            #EXITで退出
            if(exit_flag):
                receive_thread.join()
                break

    def receive(self,udp_socket):
        packet_size = 4096
        while True:
            packet, _ = udp_socket.recvfrom(packet_size)
            user_name_size = int.from_bytes(packet[:1],"big")
            user_name = packet[1:user_name_size+1].decode()
            message = packet[user_name_size+1:]
            # print(message)
            plain_text = self.client_private_key.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("\n"+user_name+": "+plain_text.decode())

        #ホストが退出
            if message == "Room has been closed by the host.":
                break

    def input_message(self,token,room_name):
        packet_size = 4096
        room_name_size = len(room_name.encode())
        token_size = len(token.encode())
        available_message_size=packet_size - (token_size + room_name_size)

        message=input("Enter message you want to send: ")

        payload={
                "message":message,
                "room_name":room_name,
                "token":token
        }
        payload_bytes=json.dumps(payload).encode()
        # encrypt with server_public_key
        cipher_payload = self.server_public_key.encrypt(
            payload_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        payload_size=len(cipher_payload)
        while payload_size>available_message_size:
            message = input("Too long. Re-Enter message you want to send: ")
            payload={
                "message":message,
                "room_name":room_name,
                "token":token}
            payload_bytes=json.dumps(payload).encode()
            # encrypt with server_public_key
            cipher_payload = self.server_public_key.encrypt(
                payload_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            payload_size=len(cipher_payload)
        if message == "EXIT":
            return cipher_payload,True
        else:
            return cipher_payload,False


    def input_info(self):
        room_name = input("Enter room name you want to create: ")
        room_name_size = len(room_name.encode())
        #room name が256バイト以下か確認
        if room_name_size > 2**8:
            print("Room name must not be over 256 bytes")
            print("FYI: This room name has "+ room_name_size + "bytes")
            room_name = input("Re-enter room name: ")
            room_name_size = len(room_name.encode())
        user_name = input("Enter your user name: ")
        password = input("Enter password for room: ")
        return room_name,user_name,password

    def input_operation(self):
        print("Which operation do you want to do")
        print("1: Create a chat room")
        print("2: Join a chat room")
        print("3: exit")
        operation=input(">")
        if operation == "3":
            sys.exit(0)
        while operation !="1" and operation !="2" and operation !="3":
            print("Invalid operation. Enter 1,2 or 3")
            operation = input(">")
        return operation

def generate_rsa_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_key_pem, private_key


if __name__ == "__main__":
    server_address="localhost"
    server_tcp_port=8000
    server_udp_port=8001
    public_key,private_key =generate_rsa_keys()
    client = Client(server_address,server_tcp_port,server_udp_port,public_key,private_key)
    client.run()
