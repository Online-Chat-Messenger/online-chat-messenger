import socket
import time
import threading

users={}
user_times={}
packet_size = 4096

def main():
    # UDPソケット
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port = 9001
    udp_socket.bind(("", port))
    print('\nwaiting to receive message')

    threading.Thread(target=check_time, daemon=True).start()

    while True:
        # メッセージの受信
        packet, sender = udp_socket.recvfrom(packet_size)
        # ユーザー名のサイズを受け取る
        user_name_size = packet[0]
        user_name = packet[1:user_name_size+1].decode()
        users[user_name] = sender
        user_times[user_name]=time.time()
        for user in users.keys():
            if user != user_name:
                udp_socket.sendto(packet,users[user])


def check_time():
    while True:
        users_to_delete = []
        current_time = time.time()
        for user, last_send_time in user_times.items():
            if current_time - last_send_time >= 10:
                users_to_delete.append(user)
        for user in users_to_delete:
            del user_times[user]
            del users[user]
        time.sleep(10)




if __name__ == "__main__":
    main()
