import os
import customtkinter as ctk
import threading
from server import *
from tkinter import filedialog
import shutil
import socket
import time
import tarfile
#  import hashlib
#  import base64
import tempfile


class FileManager(ctk.CTkToplevel):
    def __init__(self, path, master):
        super().__init__(master)
        self.wm_transient(master)
        ctk.set_appearance_mode("system")
        self.path = path
        self.geometry("950x600")
        self.nome_usuario = "nome usuario"
        self.users = {}

        self.file_list = FileList(self, self.path)
        self.user_list = UserList(self, self.users)

        self.upload_button = ctk.CTkButton(self, text="upload file", command=self.upload_file)
        self.upload_button.pack()

        self.open_button = ctk.CTkButton(self, text="open file", command=self.open_file)
        self.open_button.pack()

        self.search_users_button = ctk.CTkButton(self, text="search for nearby users", command=self.find_users)
        self.search_users_button.pack()

        self.send_file_button = ctk.CTkButton(self, text="send file", command=self.send_files)
        self.send_file_button.pack()

        self.broadcast_thread = threading.Thread(target=broadcast_myself, args=(self.nome_usuario,))
        self.broadcast_thread.start()

        self.broadcast_listen_thread = threading.Thread(target=self.listen_for_broadcasts)

        self.file_receiver_thread = threading.Thread(target=self.file_receiver)
        self.file_receiver_thread.start()

    def listen_for_broadcasts(self):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_socket.bind(('0.0.0.0', 33966))
        listen_socket.settimeout(2)  # tentei parar com socket timeout mas n deu certo

        start_time = time.time()

        while True:
            user_name, addr = listen_socket.recvfrom(1024)
            print(f" mensagem recebida: {user_name.decode()} do {addr}")

            if user_name.decode() not in self.users.keys():
                # usuario salvo em dict com forma nome:ip, e envia apenas o nome para a lista
                self.users[user_name.decode()] = addr[0]
                self.user_list.users_radiobutton.add_item(user_name.decode())

            if time.time() - start_time > 2:
                print("conexao encerrada")
                print(self.users)
                break

    def find_users(self):
        self.broadcast_listen_thread.start()

    def upload_file(self):
        try:
            file_path = filedialog.askopenfilename()
            print(file_path)
            self.file_list.add_file(file_path)
            file_name = os.path.basename(file_path)
            self.file_list.files_checkbox.add_item(file_name)
        except FileNotFoundError:
            print("no file uploaded")

    def open_file(self):
        files_to_open = self.file_list.files_checkbox.get_checked_items()
        for file in files_to_open:
            file_path = self.path + "\\" + file

            if os.path.isfile(file_path):
                print(file)
                print(file_path)
                os.startfile(file_path)
            else:
                new_file_manager = FileManager(path=file_path, master=self)

    def send_files(self):
        dest_user = self.user_list.users_radiobutton.get_checked_item()
        files = self.file_list.files_checkbox.get_checked_items()
        if dest_user != '':
            ip = self.users[dest_user]
            if files:
                for file in files:
                    file_path = self.path + "\\" + file
                    file_size = os.path.getsize(file_path)
                    if os.path.isfile(file_path):
                        file_obj = self.get_file_object(file_path)
                        send_file(file, file_obj, ip, file_size)

                    else:
                        #tentei usar isso pra mandar diretorio como arquivo, mas ainda n funciona
                        """
                        dir_name = file
                        temp_file = tempfile.NamedTemporaryFile(suffix=".tar")
                        temp_file.close()
                        self.compacta_dir(dir_name, temp_file)
                        file_obj = self.get_file_object(temp_file.name, temp_file)
                        send_file(dir_name, file_obj, ip, temp_file.tell())
                        temp_file.close()
                        """

            else:
                print("nenhum arquivo selecionado")
        else:
            print("nenhum usuario selecionado")

    def file_receiver(self):
        SEPARATOR = "<SEPARATOR>"
        buffer_size = 4096
        receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receive_socket.bind(("0.0.0.0", 44332))
        receive_socket.listen(1)

        while True:
            client_socket, addr = receive_socket.accept()

            received = client_socket.recv(buffer_size).decode()
            file_name, file_size = received.split(SEPARATOR)
            file_name = os.path.basename(file_name)

            is_dir = False
            _, ext = os.path.splitext(file_name)
            if ext == ".tar":
                is_dir = True
                print("deu certo")

            file_size = int(file_size)
            file_path = os.path.join(self.path, file_name)

            progress = tqdm.tqdm(range(file_size), f"receiving {file_path}", unit="B", unit_scale=True, unit_divisor=1024)

            with open(file_path, "wb") as file:
                bytes_read = client_socket.recv(buffer_size)
                while bytes_read:
                    file.write(bytes_read)
                    progress.update(len(bytes_read))
                    bytes_read = client_socket.recv(buffer_size)

            if is_dir:
                dir_name = file_name.split(".")[0]
                dir_name = "dir teste"
                path = os.path.join(self.path, dir_name)
                with tarfile.open(file_path, "r") as tar:
                    tar.extractall(path=dir_name)


            self.file_list.files_checkbox.add_item(file_name)
            client_socket.close()

    def compacta_dir(self, dir, temp_file):
        with tarfile.open(temp_file.name, 'w') as tar:
            tar.add(dir, arcname=os.path.basename(dir))

    def get_file_object(self, file_path, temp_file=None):
        if temp_file is not None:
            # Se for um arquivo temporário, reposicione o cursor no início e retorne o objeto
            temp_file.seek(0)
            return temp_file
        else:
            # Se for um arquivo não temporário, abra e retorne o objeto
            return open(file_path, "rb")




class UserList(ctk.CTkFrame):
    def __init__(self, master, users):
        super().__init__(master)
        self.pack(fill="both", expand=True)

        self.users_radiobutton = ScrollableFrameRadiobutton(self, [])  # esse so tem uma lista com o nome do usuario
        self.users_radiobutton.grid(row=0, column=0, padx=15, pady=15, sticky="ns")


class FileList(ctk.CTkFrame):
    def __init__(self, master, path):
        super().__init__(master)
        self.pack(fill="both", expand=True)

        self.path = path
        self.files = os.listdir(self.path)
        print(self.files)
        self.files_checkbox = ScrollableFrameCheckbox(self, width=200, file_list=self.files)
        self.files_checkbox.grid(row=0, column=0, padx=15, pady=15, sticky="ns")

    def add_file(self, file_path):
        shutil.copy(file_path, self.path)
        self.files = os.listdir(self.path)
        print(self.files)


class ScrollableFrameCheckbox(ctk.CTkScrollableFrame):
    def __init__(self, master, file_list, **kwargs):
        super().__init__(master, **kwargs)

        self.checkbox_list = []
        for file in file_list:
            self.add_item(file)

    def add_item(self, item):
        checkbox = ctk.CTkCheckBox(self, text=item)
        checkbox.grid(row=len(self.checkbox_list), column=0, pady=(0, 10))

        self.checkbox_list.append(checkbox)

    def remove_item(self, item):
        for checkbox in self.checkbox_list:
            if item == checkbox.cget("text"):
                checkbox.destroy()
                self.checkbox_list.remove(checkbox)
                return

    def get_checked_items(self):
        return [checkbox.cget("text") for checkbox in self.checkbox_list if checkbox.get() == 1]


class ScrollableFrameRadiobutton(ctk.CTkScrollableFrame):
    def __init__(self, master, users):
        super().__init__(master)
        self.user_radiobutton_var = ctk.StringVar()
        self.user_radiobutton_list = []
        for user in users:
            self.add_item(user)

    def add_item(self, item):
        radiobutton = ctk.CTkRadioButton(master=self, text=item, value=item, variable=self.user_radiobutton_var)

        radiobutton.grid(row=len(self.user_radiobutton_list), column=0, pady=(0, 10))
        self.user_radiobutton_list.append(radiobutton)

    def get_checked_item(self):
        return self.user_radiobutton_var.get()
