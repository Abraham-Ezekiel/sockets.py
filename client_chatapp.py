#!/usr/bin/env python3
import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from cryptography.fernet import Fernet

# Encryption key (use a securely exchanged key in real scenarios)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Application")
        
        # Frame for messages
        self.messages_frame = ttk.Frame(self.root, padding="10")
        self.messages_frame.grid(row=0, column=0, sticky="nsew")
        
        # ScrolledText widget for message display
        self.msg_list = scrolledtext.ScrolledText(self.messages_frame, wrap=tk.WORD, height=10, state=tk.DISABLED)
        self.msg_list.grid(row=0, column=0, columnspan=2, sticky="nsew")
        
        # Entry widget for user input
        self.msg_entry = ttk.Entry(self.root)
        self.msg_entry.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.msg_entry.bind("<Return>", self.send_message)

        # Send button
        self.send_button = ttk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.grid(row=1, column=1, padx=10, pady=10)

        # Send file button
        self.file_button = ttk.Button(self.root, text="Send File", command=self.send_file)
        self.file_button.grid(row=2, column=1, padx=10, pady=10)

        # Adjust grid configurations to expand properly
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Create socket for communication
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self, host, port):
        try:
            self.client_socket.connect((host, port))
            threading.Thread(target=self.receive_messages).start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to the server: {str(e)}")
    
    def send_message(self, event=None):
        message = self.msg_entry.get()
        if message:
            try:
                encrypted_message = cipher_suite.encrypt(message.encode())
                self.client_socket.send(encrypted_message)
                self.display_message(f"You: {message}")
                self.msg_entry.delete(0, tk.END)
            except BrokenPipeError:
                messagebox.showerror("Connection Error", "Connection to the server was lost. Please restart the client.")
            except Exception as e:
                messagebox.showerror("Send Error", f"Failed to send message: {str(e)}")
    
    def send_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    file_data = file.read()
                    encrypted_file_data = cipher_suite.encrypt(file_data)
                    self.client_socket.send(encrypted_file_data)
                self.display_message(f"File sent: {file_path}")
            except BrokenPipeError:
                messagebox.showerror("Connection Error", "Connection to the server was lost. Please restart the client.")
            except Exception as e:
                messagebox.showerror("File Send Error", f"Failed to send file: {str(e)}")

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024)
                if not message:
                    raise ConnectionResetError("Server closed the connection.")
                decrypted_message = cipher_suite.decrypt(message).decode()
                self.display_message(f"Server: {decrypted_message}")
            except ConnectionResetError:
                messagebox.showerror("Connection Lost", "Connection to the server was closed.")
                break
            except Exception as e:
                messagebox.showerror("Receive Error", f"Error receiving message: {str(e)}")
                break

    def display_message(self, message):
        self.msg_list.config(state=tk.NORMAL)
        self.msg_list.insert(tk.END, f"{message}\n")
        self.msg_list.config(state=tk.DISABLED)
        self.msg_list.yview(tk.END)

def start_client():
    root = tk.Tk()
    client_gui = ClientGUI(root)
    
    # You can adjust the host and port here
    host = "localhost"
    port = 8080
    
    try:
        client_gui.connect(host, port)
        root.mainloop()
    except KeyboardInterrupt:
        print("\nClient application closed by user.")
    finally:
        client_gui.client_socket.close()

if __name__ == "__main__":
    start_client()

