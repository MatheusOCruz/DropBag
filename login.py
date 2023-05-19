import customtkinter as ctk


class LoginFrame(ctk.CTkFrame):
    def __init__(self, master, on_successful_login):
        super().__init__(master)

        self.pack(pady=20, padx=60, fill="both", expand=True)

        self.on_successful_login = on_successful_login

        self.login_label = ctk.CTkLabel(master=self, text="Login")
        self.login_label.pack()

        self.username_entry = ctk.CTkEntry(master=self, placeholder_text="username")
        self.username_entry.pack(pady=12, padx=10)

        self.password_entry = ctk.CTkEntry(master=self, placeholder_text="password", show='*')
        self.password_entry.pack(pady=12, padx=10)

        self.login_button = ctk.CTkButton(master=self, text='login', command=self.login)
        self.login_button.pack(pady=12, padx=10)

    @staticmethod
    def validate_login(username, password):
        # jeito besta pra teste
        if username == password:
            return True
        return False

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if self.validate_login(username, password):
            print('eba')
            self.on_successful_login()
        else:
            print("ta errado patrão")
