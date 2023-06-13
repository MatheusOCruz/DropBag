import socket
import time
import tqdm


def broadcast_myself(mensagem):
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # socket UDP para broadcast
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        broadcast_socket.sendto(mensagem.encode('utf-8'), ('255.255.255.255', 33966))
        time.sleep(3)


def ask_has_folder(folder):
    ask_has_folder_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ask_has_folder_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    start_time = time.time()
    while time.time() - start_time <= 30:
        message = f"<FOLDER_REQUEST>{folder},chave"
        ask_has_folder_socket.sendto(message.encode('utf-8'), ('255.255.255.255', 33966))
        time.sleep(5)


def send_file(file_name, file_path, ip, file_size, port):
    separator = "<SEPARATOR>"
    delimiter = b"\\0j0"
    buffer_size = 4096 - len(delimiter)
    send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    send_socket.connect((ip, port))
    send_socket.send(f'{file_name}{separator}{file_size}'.encode())

    progress = tqdm.tqdm(range(file_size), f"Sending {file_name}", unit="B", unit_scale=True, unit_divisor=1024)

    with open(file_path, "rb") as f:
        chunk = f.read(buffer_size)
        while chunk:
            send_socket.sendall(chunk + delimiter)
            progress.update(len(chunk))
            chunk = f.read(buffer_size)

    send_socket.close()


def get_ip_address():
    try:
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        temp_socket.connect(("8.8.8.8", 80))

        ip_address = temp_socket.getsockname()[0]

        temp_socket.close()
        print(ip_address)
        return ip_address
    except socket.error:
        return "Unable to retrieve IP address."
