from datetime import datetime
import os
import customtkinter as ctk
import threading
from server import *
from tkinter import filedialog
import shutil
import socket
import json
import hashlib
import zipfile
import filecmp
import re


def save_to_json(json_name, json_string):
    with open(json_name, "w") as file:
        file.write(json_string)


def zip_dir(dir_path, output_path):
    with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, dir_path)
                zipf.write(file_path, arcname)


def unzip_file(zip_path, output_dir):
    with zipfile.ZipFile(zip_path, 'r') as zipf:
        zipf.extractall(output_dir)


class FileManager(ctk.CTkToplevel):
    def __init__(self, path, master):
        super().__init__(master)
        self.wm_transient(master)
        ctk.set_appearance_mode("system")
        self.ip = get_ip_address()
        self.title = "Dropbag"
        self.path = path
        self.old_paths = []
        self.geometry("950x600")

        self.nome_usuario = input("user_name:")
        self.users = {}
        self.shared_folders = []
        self.load_shared_folders()

        self.file_list = FileList(self, self.path)
        self.user_list = UserList(self, self.users)

        self.update_folders_have_json()

        self.upload_button = ctk.CTkButton(self, text="upload file", command=self.upload_file)
        self.upload_button.pack(side="left", padx=5, pady=5)

        self.open_button = ctk.CTkButton(self, text="open file", command=self.open_file)
        self.open_button.pack(side="left", padx=5, pady=5)

        self.send_file_button = ctk.CTkButton(self, text="send file", command=self.send_files)
        self.send_file_button.pack(side="left", padx=5, pady=5)

        self.share_folder_button = ctk.CTkButton(self, text="share folder", command=self.share_folders)
        self.share_folder_button.pack(side="left", padx=5, pady=5)

        self.sync_folders_button = ctk.CTkButton(self, text="sync folders", command=self.sync_folders)
        self.sync_folders_button.pack(side="left", padx=5, pady=5)

        self.broadcast_thread = threading.Thread(target=broadcast_myself, args=(self.nome_usuario,))
        self.broadcast_thread.start()

        self.broadcast_listen_thread = threading.Thread(target=self.listen_for_broadcasts)
        self.broadcast_listen_thread.start()

        self.file_receiver_thread = threading.Thread(target=self.file_receiver)
        self.file_receiver_thread.start()

        self.auto_sync_thread = threading.Thread(target=self.auto_sync_folders)

    def listen_for_broadcasts(self):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_socket.bind(('0.0.0.0', 33966))

        try:
            while True:
                mensagem = listen_socket.recvfrom(1024)
                data, (ip, porta) = mensagem[0], mensagem[1]
                data = data.decode()
                if ip == self.ip:
                    continue
                if data.startswith("<FOLDER_REQUEST>"):
                    data = data[data.find(">") + 1:]
                    folder, chave = data.split(",")
                    print(folder)
                    print(ip)
                    # falta verificacao da chave do folder
                    if folder in os.listdir(self.path):
                        folder_json = f'{folder}.json'
                        json_path = os.path.join(self.path, folder_json)
                        json_size = os.path.getsize(json_path)
                        send_file(folder_json, json_path, ip, json_size, 63636)
                        self.send_requested_files(folder, ip)


                else:
                    user_name = data
                    if user_name not in self.users.keys():
                        self.users[user_name] = ip
                        self.user_list.users_radiobutton.add_item(user_name)

        except socket.timeout:
            print("timeout queridao")

    def send_requested_files(self, folder, ip):
        file_list_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        file_list_socket.bind(("0.0.0.0", 27727))
        file_list_socket.listen(1)
        file_list_socket.settimeout(10)
        try:
            file_soc, addr = file_list_socket.accept()
            json_arquivos = file_soc.recv(4096).decode()
            file_soc.close()
            arquivos_desejados = json.loads(json_arquivos)

            folder_path = os.path.join(self.path, folder)
            temp_zip = f'{folder}_2.zip'
            temp_zip_path = os.path.join(self.path, temp_zip)
            with zipfile.ZipFile(temp_zip_path, 'w') as zipf:
                for file in arquivos_desejados:
                    file_path = os.path.join(folder_path, file)
                    zipf.write(file_path, file)
            file_path = os.path.join(self.path, temp_zip)
            file_size = os.path.getsize(file_path)
            send_file(temp_zip, file_path, ip, file_size, 27727)
            os.remove(file_path)



        except socket.timeout:
            print('le timeoute')

    def auto_sync_folders(self):
        with open(os.path.join(self.path, "shared_folders.json"), 'r') as f:
            folders = json.load(f)
        for folder in folders:
            self.sync_folder(folder)
            time.sleep(5)
        time.sleep(180)

    def sync_folders(self):
        folders_to_sync = self.file_list.files_checkbox.get_checked_items()

        for folder in folders_to_sync:
            folder_path = self.path + "\\" + folder
            if os.path.isfile(folder_path):
                continue
            self.sync_folder(folder)
            time.sleep(2)

    def sync_folder(self, folder):
        print(folder)
        ask_has_folder_thread = threading.Thread(target=ask_has_folder, args=(folder,))
        ask_has_folder_thread.start()

        SEPARATOR = "<SEPARATOR>"
        delimiter = b"\\0j0"
        buffer_size = 4096

        get_json_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        get_json_socket.bind(("0.0.0.0", 63636))
        get_json_socket.settimeout(10)
        get_json_socket.listen(1)

        try:
            client_socket, addr = get_json_socket.accept()
            folder_owner_ip = addr[0]
            received = client_socket.recv(buffer_size).decode()

            file_name, file_size = received.split(SEPARATOR)
            file_name = "dir1_2.json"

            file_size = int(file_size)

            file_path = os.path.join(self.path, file_name)

            progress = tqdm.tqdm(range(file_size), f"receiving {file_path}", unit="B", unit_scale=True,
                                 unit_divisor=1024)

            with open(file_path, "wb") as file:
                bytes_read = client_socket.recv(buffer_size)
                while bytes_read:
                    if bytes_read.find(delimiter) != -1:
                        bytes_read = bytes_read[:bytes_read.find(delimiter)]
                        file.write(bytes_read)
                        progress.update(len(bytes_read))
                        bytes_read = client_socket.recv(buffer_size)
            client_socket.close()
            get_json_socket.close()
            current_json = os.path.join(self.path, f'{folder}.json')
            self.compare_jsons(current_json, file_path, folder_owner_ip, folder)

        except socket.timeout:
            print('timeout chefe')

    def compare_jsons(self, current, new, folder_owner_ip, folder):
        with open(current, 'r') as f:
            current_data = json.load(f)
        with open(new, 'r') as f:
            new_data = json.load(f)
        files_to_request = []
        for k, v in new_data.items():
            if k not in current_data:
                files_to_request.append(k)
                continue

            new_date = datetime.strptime(new_data[k]["last_edited"], "%Y-%m-%d %H:%M:%S")
            current_date = datetime.strptime(current_data[k]["last_edited"], "%Y-%m-%d %H:%M:%S")
            print(new_date, current_date)
            if new_date > current_date and new_data[k]['hash'] == current_data[k]['hash']:
                files_to_request.append(k)
        os.remove(new)
        print(files_to_request)
        if files_to_request:
            SEPARATOR = "<SEPARATOR>"
            delimiter = b"\\0j0"
            buffer_size = 4096
            json_files = json.dumps(files_to_request)
            files_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            files_socket.connect((folder_owner_ip, 27727))
            files_socket.sendall(json_files.encode())
            files_socket.close()
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            recv_socket.bind(('0.0.0.0', 27727))
            recv_socket.listen(1)
            try:
                receive_soq, addr = recv_socket.accept()
                received = receive_soq.recv(buffer_size).decode()
                file_name, file_size = received.split(SEPARATOR)
                print(file_name)
                file_size = int(file_size)

                file_path = os.path.join(self.path, file_name)

                progress = tqdm.tqdm(range(file_size), f"receiving {file_path}", unit="B", unit_scale=True,
                                     unit_divisor=1024)

                with open(file_path, "wb") as file:
                    bytes_read = receive_soq.recv(buffer_size)
                    while bytes_read:
                        if bytes_read.find(delimiter) != -1:
                            bytes_read = bytes_read[:bytes_read.find(delimiter)]
                            file.write(bytes_read)
                            progress.update(len(bytes_read))
                            bytes_read = receive_soq.recv(buffer_size)
                    receive_soq.close()
                    recv_socket.close()
                    file.close()
                    dir_name = file_name[:-4]
                    dir_path = os.path.join(self.path, dir_name)
                    os.makedirs(dir_path)
                    print(file_path)
                    unzip_file(zip_path=file_path, output_dir=dir_path)
                    os.remove(file_path)
                    current_folder_path = os.path.join(self.path, folder)
                    print("chegou")
                    self.compare_folders(current_folder_path, dir_path)
                    print("passou")

                    ## os.remove(dir_path) ainda n da pra remover (da acesso negado)

            except socket.timeout:
                print('timeout pra variar')

    def compare_folders(self, current_folder_path, new_folder_path):
        folder_json = os.path.join(self.path, f'{current_folder_path}.json')
        with open(folder_json, 'r') as f:
            data = json.load(f)
        f.close()

        new_files = os.listdir(new_folder_path)
        for file in new_files:
            file_path = os.path.join(new_folder_path, file)
            if not os.path.exists(os.path.join(current_folder_path, file)):
                shutil.copy2(file_path, current_folder_path)
                file_data = self.get_file_info(file_path)
                data[file] = file_data
            elif filecmp.cmp(file_path, os.path.join(current_folder_path, file)) == False:
                old_file_time = data[file]['last_edited'].replace(" ", "_").replace(":", "-")
                print(file)
                new_name = f'{file}_{old_file_time}'
                old_file_path = os.path.join(current_folder_path, file)
                os.rename(os.path.join(current_folder_path, file), os.path.join(current_folder_path, new_name))
                print(file_path)
                print(current_folder_path)
                shutil.copy2(file_path, current_folder_path)
        shutil.rmtree(new_folder_path)
        json_string = json.dumps(data, indent=4)
        save_to_json(folder_json, json_string)
        f.close()

    def check_last_edited(self):
        files = os.listdir(self.path)

        for file in files:
            file_path = os.path.join(self.path, file)
            if file_path.endswith(".json") or os.path.isdir(file_path):
                continue
            file_name = os.path.splitext(file)[0]
            file_json = f"{file_name}.json"
            file_json = os.path.join(self.path, file_json)
            with open(file_json) as f:
                json_data = json.load(f)
            last_edited = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
            if last_edited != json_data["last_edited"]:
                json_data['last_edited'] = last_edited

                new_hash = self.get_hash(file_path)
                json_data['hash'].append(new_hash)

                json_string = json.dumps(json_data, indent=4)

                save_to_json(file_json, json_string)

    def upload_file(self):
        try:
            file_path = filedialog.askopenfilename()
            print(file_path)
            self.file_list.add_file(file_path)
            file_name = os.path.basename(file_path)
            self.file_list.files_checkbox.add_item(file_name)


        except FileNotFoundError:
            print("no file uploaded")

    def check_all_files_have_json(self):
        files = os.listdir(self.path)

        for file in files:
            file_path = os.path.join(self.path, file)
            if file_path.endswith(".json") or os.path.isdir(file_path):
                continue

            json_file = file.split(".")[0] + ".json"
            if json_file not in files:
                self.make_json(file_path)

    def update_folders_have_json(self):
        files = os.listdir(self.path)
        for file in files:
            if os.path.isdir(os.path.join(self.path, file)):
                self.folder_json(os.path.join(self.path, file))

    def folder_json(self, folder_path):
        files = os.listdir(folder_path)
        folder = os.path.basename(folder_path)
        json_path = os.path.join(self.path, f'{folder}.json')
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                folder_info = json.load(f)
            for file in files:
                print(file)
                if file.endswith(".json"):
                    continue
                file_path = os.path.join(folder_path, file)
                if os.path.isdir(file_path):
                    pass
                    # n vamos considerar folder com folders ent n vou usar
                else:
                    regex = r'^(.*?)_\d{4}-\d{1,2}-\d{1,2}_\d{1,2}-\d{1,2}-\d{1,2}\.\w+$'
                    regex2 = r'^(.*?)_\d{4}-\d{1,2}-\d{1,2}_\d{1,2}-\d{1,2}-\d{1,2}'
                    if re.match(regex, file) or re.match(regex2, file):
                        continue
                    file_info = self.get_file_info(file_path)
                    if file in folder_info:
                        folder_info[file]["last_edited"] = file_info["last_edited"]
                    else:
                        folder_info[file] = self.get_file_info(file_path)



        else:
            folder_info = {}
            for file in files:
                if file.endswith(".json"):
                    continue
                file_path = os.path.join(folder_path, file)

                if os.path.isdir(file_path):
                    folder_info[file] = self.folder_json(file_path)

                else:
                    folder_info[file] = self.get_file_info(file_path)

        json_string = json.dumps(folder_info, indent=4)

        json_name = os.path.basename(folder_path).split(".")[0] + ".json"
        json_path = os.path.join(self.path, json_name)
        save_to_json(json_path, json_string)
        return folder_info

    def get_file_info(self, file_path):
        creation_date = datetime.fromtimestamp(os.path.getctime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
        print(creation_date)
        last_edited = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M:%S")
        print(last_edited)
        hash_hex = self.get_hash(file_path)
        file_info = {"creation_date": creation_date,
                     "last_edited": last_edited,
                     "hash": hash_hex}
        return file_info

    def get_hash(self, file_path):
        with open(file_path, "rb") as file:
            file_content = file.read()
            hash_obj = hashlib.sha1(file_content)
            return hash_obj.hexdigest()

    def open_file(self):
        files_to_open = self.file_list.files_checkbox.get_checked_items()
        for file in files_to_open:
            file_path = self.path + "\\" + file

            if os.path.isfile(file_path):
                print(file)
                print(file_path)
                os.startfile(file_path)
            else:
                self.old_paths.insert(0, self.path)
                self.path = file_path
                print(file_path)
                self.file_list.reset(self.path)
                break

    def share_folders(self):
        dest_user = self.user_list.users_radiobutton.get_checked_item()
        folders_to_share = self.file_list.files_checkbox.get_checked_items()

        for folder in folders_to_share:
            folder_path = self.path + "\\" + folder
            if os.path.isfile(folder_path):
                continue
            self.share_folder(folder_path, folder, dest_user)

    def share_folder(self, folder_path, folder_name, dest_user):
        zip_file_name = f"{folder_name}.zip"
        zip_path = os.path.join(self.path, zip_file_name)
        zip_dir(folder_path, zip_path)
        ip = self.users[dest_user]
        zip_size = os.path.getsize(zip_path)
        send_file(zip_file_name, zip_path, ip, zip_size, 44332)
        os.remove(zip_path)
        with open(os.path.join(self.path, "shared_folders.json"), 'r') as f:
            data = json.load(f)
        data.append(folder_name)
        f.close()
        with open(os.path.join(self.path, "shared_folders.json"), 'w') as f:
            json.dump(data, f)

    def load_shared_folders(self):
        shared_f_json = "shared_folders.json"
        shared_f_j_path = os.path.join(self.path, shared_f_json)
        try:
            with open(shared_f_j_path, 'w') as f:
                self.shared_folders = json.load(f)

        except:
            data = []
            with open(shared_f_j_path, 'w') as f:
                json.dump(data, f)
            f.close()

    def send_files(self):
        dest_user = self.user_list.users_radiobutton.get_checked_item()
        files = self.file_list.files_checkbox.get_checked_items()
        if dest_user != '':
            ip = self.users[dest_user]
            if files:
                for file in files:

                    file_name = os.path.splitext(file)[0]
                    file_json = f"{file_name}.json"
                    file_json = os.path.join(self.path, file_json)
                    with open(file_json) as f:
                        json_data = json.load(f)

                    if json_data['shared'] == False:
                        json_data['shared'] = True

                        json_string = json.dumps(json_data, indent=4)

                        json_path = os.path.join(self.path, file_json)
                        save_to_json(json_path, json_string)

                    file_path = self.path + "\\" + file
                    file_size = os.path.getsize(file_path)
                    if os.path.isfile(file_path):
                        send_file(file, file_path, ip, file_size, 44332)

            else:
                print("nenhum arquivo selecionado")
        else:
            print("nenhum usuario selecionado")

    def file_receiver(self):
        SEPARATOR = "<SEPARATOR>"
        delimiter = b"\\0j0"
        buffer_size = 4096
        receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receive_socket.bind(("0.0.0.0", 44332))
        receive_socket.listen(1)

        while True:
            client_socket, addr = receive_socket.accept()
            is_zip = False
            received = client_socket.recv(buffer_size).decode()

            file_name, file_size = received.split(SEPARATOR)
            if file_name.endswith(".zip"):
                is_zip = True
                print('zip')

            file_size = int(file_size)
            file_path = os.path.join(self.path, file_name)

            progress = tqdm.tqdm(range(file_size), f"receiving {file_path}", unit="B", unit_scale=True,
                                 unit_divisor=1024)

            with open(file_path, "wb") as file:
                bytes_read = client_socket.recv(buffer_size)
                while bytes_read:
                    if bytes_read.find(delimiter) != -1:
                        bytes_read = bytes_read[:bytes_read.find(delimiter)]
                        file.write(bytes_read)
                        progress.update(len(bytes_read))
                        bytes_read = client_socket.recv(buffer_size)
            client_socket.close()
            if is_zip:
                dir_name = file_name[:-4]
                dir_path = os.path.join(self.path, dir_name)
                os.makedirs(dir_path)
                unzip_file(zip_path=file_path, output_dir=dir_path)
                self.file_list.files_checkbox.add_item(dir_name)
                zip_file = os.path.join(self.path, file_name)
                os.remove(zip_file)
            else:
                self.file_list.files_checkbox.add_item(file_name)


class UserList(ctk.CTkFrame):
    def __init__(self, master, users):
        super().__init__(master)
        self.pack(fill="both", expand=True)

        self.users_radiobutton = ScrollableFrameRadiobutton(self, [])  # esse so tem uma lista com o nome do usuario
        self.users_radiobutton.grid(row=0, column=0, padx=15, pady=15, sticky="ns")


class FileList(ctk.CTkFrame):
    def __init__(self, master, path):
        super().__init__(master, width=400, height=200)
        self.pack(fill="both", expand=True)
        self.path = path
        self.files = os.listdir(self.path)
        # os arquivos json nao devem ser listados
        self.files = [file for file in self.files if not file.endswith(".json")]
        self.files_checkbox = ScrollableFrameCheckbox(self, file_list=self.files)
        self.files_checkbox.grid(row=0, column=0, padx=15, pady=15, sticky="ns")

    def add_file(self, file_path):
        shutil.copy(file_path, self.path)
        self.files = os.listdir(self.path)
        print(self.files)

    def reset(self, new_path):
        self.path = new_path
        self.files = os.listdir(self.path)
        self.files = [file for file in self.files if not file.endswith(".json")]
        self.files_checkbox = ScrollableFrameCheckbox(self, file_list=self.files)
        self.files_checkbox.grid(row=0, column=0, padx=15, pady=15, sticky="ns")


class ScrollableFrameCheckbox(ctk.CTkScrollableFrame):
    def __init__(self, master, file_list):
        super().__init__(master, width=600, height=200)

        self.checkbox_list = []
        for file in file_list:
            self.add_item(file)

    def reset(self, new_file_list):
        for checkbox in self.checkbox_list:
            checkbox.destroy()
            self.checkbox_list.remove(checkbox)

        for file in new_file_list:
            self.add_item(file)

    def add_item(self, item):
        checkbox = ctk.CTkCheckBox(self, text=item)
        checkbox.grid(row=len(self.checkbox_list), column=0, pady=(0, 10), sticky=ctk.W)

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
