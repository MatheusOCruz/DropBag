import socket
import time
import tqdm
import hashlib
import base64


def broadcast_myself(mensagem):
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # socket UDP para broadcast
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        broadcast_socket.sendto(mensagem.encode('utf-8'), ('255.255.255.255', 33966))
        time.sleep(1)


def send_file(file_name, file_obj, ip, file_size):
    SEPARATOR = "<SEPARATOR>"
    buffer_size = 4096

    send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    send_socket.connect((ip, 44332))
    send_socket.send(f'{file_name}{SEPARATOR}{file_size}'.encode())

    progress = tqdm.tqdm(range(file_size), f"Sending {file_name}", unit="B", unit_scale=True, unit_divisor=1024)

    chunk = file_obj.read(buffer_size)
    while chunk:
        send_socket.sendall(chunk)
        progress.update(len(chunk))
        chunk = file_obj.read(buffer_size)

    send_socket.close()


"""
def sha1_calc(file):
    sha1 = hashlib.sha1()

    with open(file, "rb") as file:
        chunk = file.read(8192)
        while chunk:
            sha1.update(chunk)
            chunk = file.read(8192)

    return sha1.hexdigest()

"""
