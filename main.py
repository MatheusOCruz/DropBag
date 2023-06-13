import os
from os import path, makedirs
import customtkinter as ctk
from file_manager import FileManager


class DropBag(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.path = path.dirname(path.abspath(__file__))
        self.geometry("500x350")
        self.title('Drop Bag')
        self.resizable(True, True)
        self.withdraw()
        self.check_main_path_exists()
        file_manager = FileManager(self.path, self)

    def check_main_path_exists(self):
        dir_name = "all files"
        self.path = path.join(self.path, dir_name)
        if not path.exists(self.path):
            makedirs(self.path)





app = DropBag()
app.mainloop()
