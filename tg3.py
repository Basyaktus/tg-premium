from tkinter import scrolledtext, Tk, Frame, messagebox, BOTH, X, Y, END, DISABLED, LEFT, RIGHT
from tkinter import ttk
from datetime import datetime
import hashlib
import os
import pickle

class Post:
    def __init__(self, nickname, post_text):
        self.nickname = nickname
        self.time_of_post = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.post_text = post_text

    def __str__(self):
        return f"{self.nickname} {self.time_of_post}\n{self.post_text}"

class User:
    def __init__(self, login, password):
        self.login = login
        self.password = password
        self.posts = []
        self.friends = []
        self.chats = {}

    def add_post(self, post):
        self.posts.append(post)

    def add_chat(self, chat_name):
        if chat_name not in self.chats:
            self.chats[chat_name] = []

    def add_message_to_chat(self, chat_name, message):
        if chat_name in self.chats:
            self.chats[chat_name].append(message)

class ChatApplication:
    def __init__(self, user):
        self.user = user
        self.user.chats = self.load_chats()
        self.open_main_window()

    def save_chats(self):
        with open("chats_data.pkl", "wb") as f:
            pickle.dump(self.user.chats, f)

    def load_chats(self):
        if os.path.exists("chats_data.pkl"):
            with open("chats_data.pkl", "rb") as f:
                return pickle.load(f)
        return {}

    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

    def open_main_window(self):
        main_window = Tk()  
        main_window.title("Telegram")
        self.center_window(main_window, 800, 600)
        
        main_frame = Frame(main_window)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=20)
        
        chat_list_frame = Frame(main_frame, width=200)
        chat_list_frame.pack(side=LEFT, fill=Y, padx=10, pady=10)
        
        chat_frame = Frame(main_frame, relief="ridge", borderwidth=2)
        chat_frame.pack(side=RIGHT, fill=BOTH, expand=True)
        
        main_label = ttk.Label(chat_list_frame, text="Your chats", font=("Arial", 15, "bold"))
        main_label.pack(pady=20)
        
        chat_btn = ttk.Button(chat_list_frame, text="Vladik", width=20, command=lambda: self.open_chat_window(chat_frame, "Vladik"))
        chat_btn.pack(pady=10)
        
        chat_btn2 = ttk.Button(chat_list_frame, text="Dima", width=20, command=lambda: self.open_chat_window(chat_frame, "Dima"))
        chat_btn2.pack(pady=10)
        
        main_window.mainloop()

    def open_chat_window(self, chat_frame, chat_name):
        for widget in chat_frame.winfo_children():
            widget.destroy()
        
        chat_label = ttk.Label(chat_frame, text=f"Chat with {chat_name}", font=("Arial", 15, "bold"))
        chat_label.pack(pady=10)
        
        history_text = scrolledtext.ScrolledText(chat_frame, width=40, height=20, state=DISABLED)
        history_text.pack(fill=BOTH, expand=True, pady=10)
        
        self.user.add_chat(chat_name)
        
        if chat_name in self.user.chats:
            history_text.config(state="normal")
            for post in self.user.chats[chat_name]:
                history_text.insert(END, f"{post}\n")
            history_text.config(state=DISABLED)
        
        input_frame = Frame(chat_frame)
        input_frame.pack(fill=X, pady=10, padx=10)
        
        post_text = scrolledtext.ScrolledText(input_frame, width=40, height=5)
        post_text.pack(side=LEFT, fill=BOTH, expand=True, padx=10)

        post_text.bind("<Return>", lambda e: self.post_message(chat_name, post_text, history_text))
        post_text.bind("<Escape>", lambda e: post_text.delete("1.0", END))
        
        post_button = ttk.Button(input_frame, text="Post", command=lambda: self.post_message(chat_name, post_text, history_text))
        post_button.pack(side=RIGHT, padx=10)

    def post_message(self, chat_name, post_text, history_text):
        post_content = post_text.get("1.0", END).strip()
        if post_content:
            post = Post(self.user.login, post_content)
            self.user.add_post(post)
            self.user.add_message_to_chat(chat_name, post)
            self.save_chats()
            history_text.config(state="normal")
            history_text.insert(END, f"{post}\n")
            history_text.config(state=DISABLED)
            post_text.delete("1.0", END)

class AuthenticationGUI:
    def __init__(self):
        self.root = Tk()
        self.root.title("Authentication")
        self.center_window(self.root, 400, 300)
        self.root.protocol("WM_DELETE_WINDOW", self.root.quit)
        
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 10), padding=6)
        style.configure("TLabel", font=("Arial", 10))

        main_label = ttk.Label(self.root, text="Authentication", font=("Arial", 15, "bold"))
        main_label.pack(pady=10)

        username_label = ttk.Label(self.root, text="Username")
        username_label.pack(pady=(10, 0))

        self.username_entry = ttk.Entry(self.root, width=30)
        self.username_entry.pack(pady=(0, 10))

        password_label = ttk.Label(self.root, text="Password")
        password_label.pack(pady=(10, 0))

        self.password_entry = ttk.Entry(self.root, width=30, show="*")
        self.password_entry.pack(pady=(0, 10))

        btn_create = ttk.Button(self.root, text="Sign Up", width=15, command=self.create_password_gui)
        btn_create.pack(pady=5)

        btn_check = ttk.Button(self.root, text="Log In", width=15, command=self.check_password_gui)
        btn_check.pack(pady=5)

        self.root.mainloop()

    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

    def save_users(self, users):
        with open("users_data.pkl", "wb") as f:
            pickle.dump(users, f)

    def load_users(self):
        if os.path.exists("users_data.pkl"):
            with open("users_data.pkl", "rb") as f:
                return pickle.load(f)
        return {}

    def create_password(self, username, password):
        salt = os.urandom(16)
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt, hashed_password

    def check_password(self, stored_salt, stored_hash, password):
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), stored_salt, 100000)
        return hashed_password == stored_hash

    def create_password_gui(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username:
            messagebox.showerror("Error", "Username field cannot be empty.")
            return
        if not password:
            messagebox.showerror("Error", "Password field cannot be empty.")
            return
        salt, hashed_password = self.create_password(username, password)
        users = self.load_users()
        users[username] = (salt, hashed_password)
        self.save_users(users)
        messagebox.showinfo("Success", "Password created and stored securely.")

    def check_password_gui(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username:
            messagebox.showerror("Error", "Username field cannot be empty.")
            return
        if not password:
            messagebox.showerror("Error", "Password field cannot be empty.")
            return
        try:
            users = self.load_users()
            if username in users:
                stored_salt, stored_hash = users[username]
                if self.check_password(stored_salt, stored_hash, password):
                    messagebox.showinfo("Success", "Password is correct.")
                    self.root.destroy()
                    user = User(username, password)
                    ChatApplication(user)
                else:
                    messagebox.showerror("Error", "Username or password is incorrect.")
            else:
                messagebox.showerror("Error", "Username or password is incorrect.")
        except FileNotFoundError:
            messagebox.showerror("Error", "No stored password found. Please create a password first.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    AuthenticationGUI()
