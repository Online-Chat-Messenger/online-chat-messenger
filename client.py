import socket
import threading
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class TCPClientSocket:
    def __init__(self):
        self.server_public_key = None
        self.client_public_key,self.client_private_key = self.generate_rsa_keys()
        #public_key_size = len(public_key)
        # print(public_key)
    def main(self):
        try:
            server_address="localhost"
            server_port=9000

            while True:
                #TCPでリクエスト送信
                tcp_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                tcp_socket.connect((server_address,server_port))
                local_ip, local_port = tcp_socket.getsockname()  # ローカルIPとポート番号を取得
                #1でルーム作成print
                ("Which operation do you want to do")
                print("1: Create a chat room")
                print("2: Join a chat room")
                print("3: exit")
                operation=input(">")
                if operation == "3":
                    break
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
                password = input("Enter password: ")
                state="0"
                #operation_payload=user_name
                

                
                payload = {"room_name":room_name,"user_name":user_name,"password":password,"public_key":self.client_public_key.decode()}
                # print(payload)
                operation_payload = json.dumps(payload)
                operation_payload_size=len(operation_payload.encode())
                
                #header = room_name_size.to_bytes(1,"big") + operation.encode() + state.encode() + operation_payload_size.to_bytes(29,"big")
                
                header_content = {
                    "operation":operation,
                    "state":state,
                    "operation_payload_size":operation_payload_size
                }
                
                header_json = json.dumps(header_content).encode()
                
                header_size = len(header_json)
                header = header_size.to_bytes(1,"big") + header_json
                
                tcp_socket.sendall(header)
                tcp_socket.sendall(operation_payload.encode())

                if operation == "1":
                    header = tcp_socket.recv(30)
                    status = header[:1].decode()
                    operation_payload_size = int.from_bytes(header[1:],"big")
                    operation_payload = tcp_socket.recv(operation_payload_size).decode()
                    if status =="1":
                        token = operation_payload
                        print("successfully created")
                    elif status =="2":
                        print(operation_payload)

                elif operation == "2":
                    header = tcp_socket.recv(30)
                    status = header[:1].decode()
                    operation_payload_size=int.from_bytes(header[1:],"big")
                    operation_payload = tcp_socket.recv(operation_payload_size).decode()
                    if status =="2":
                        print(operation_payload)
                        continue
                    else:
                        token = operation_payload

                server_public_key = tcp_socket.recv(4096)
                server_public_key = serialization.load_pem_public_key(server_public_key)
                self.server_public_key = server_public_key
                tcp_socket.close()
                self.send_message(room_name,token,local_port)

        #2でルーム参加
        except ChildProcessError:
            pass

    def send_message(self,room_name,token,local_port):
        packet_size = 4096

        # UDPソケット
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind(("",local_port))
        server_address = "localhost"
        server_port = 9001

        room_name_size = len(room_name.encode())
        token_size = len(token.encode())

        available_message_size=packet_size - (token_size + room_name_size)

        threading.Thread(target=self.receive,daemon=True, args=(udp_socket,)).start()

        while True:
            # Enter message
            message = input("Enter message you want to send: ")
            # print(message)
            message = message.encode()
            # encrypt with server_public_key
            cipher_message = self.server_public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # print(cipher_message)
            message_size=len(cipher_message)
            while message_size>available_message_size:
                message = input("Too long. Re-Enter message you want to send: ")
                message_size=len(cipher_message)
            udp_socket.sendto(room_name_size.to_bytes(1, "big")+token_size.to_bytes(1, "big")+(room_name+token).encode()+cipher_message,(server_address,server_port))

    def receive(self,udp_socket):
        packet_size = 4096
        while True:
            packet, _ = udp_socket.recvfrom(packet_size)
            user_name_size = int.from_bytes(packet[:1],"big")
            user_name = packet[1:user_name_size+1].decode()
            message = packet[user_name_size+1:]
            # print(message)
            plaintext = self.client_private_key.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("\n"+user_name+": "+plaintext.decode())

    def generate_rsa_keys(self):

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )


        public_key = private_key.public_key()

        public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key_bytes, private_key
if __name__ == "__main__":
    TCP_Client = TCPClientSocket()
    TCP_Client.main()