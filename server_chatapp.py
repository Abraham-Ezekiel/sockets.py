#!/usr/bin/env python3

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

class Server(threading.Thread):
    def __init__(self, host, port, allowed_ips, log_area):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port
        self.allowed_ips = allowed_ips
        self.log_area = log_area
        self.server_socket = None

    def run(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.log_area.insert(tk.END, f"Server listening at {self.server_socket.getsockname()}\n")

            while True:
                client_socket, client_address = self.server_socket.accept()
                ip_address, port = client_address

                # Check if the client's IP is in the allowlist
                if ip_address in self.allowed_ips:
                    self.log_area.insert(tk.END, f"Accepted new connection from {client_address}\n")
                    server_socket = ServerSocket(client_socket, client_address, self)
                    server_socket.start()
                    self.connections.append(server_socket)
                else:
                    self.log_area.insert(tk.END, f"Rejected connection from {client_address}\n")
                    client_socket.close()

        except Exception as e:
            messagebox.showerror("Server Error", f"Error occurred while running the server: {str(e)}")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def broadcast(self, message, source):
        for connection in self.connections:
            if connection.sockname != source:
                try:
                    connection.send(message)
                except Exception as e:
                    self.log_area.insert(tk.END, f"Error sending message to {connection.sockname}: {str(e)}\n")

    def remove_connection(self, connection):
        self.connections.remove(connection)
        self.log_area.insert(tk.END, f"Connection {connection.sockname} removed\n")


class ServerSocket(threading.Thread):
    def __init__(self, client_socket, client_address, server):
        super().__init__()
        self.client_socket = client_socket
        self.sockname = client_address
        self.server = server

    def run(self):
        try:
            while True:
                message = self.client_socket.recv(1024)
                if message:
                    self.server.log_area.insert(tk.END, f"Received from {self.sockname}: {decrypted_message.decode()}\n")
                    self.server.broadcast(message, self.sockname)
                else:
                    self.server.log_area.insert(tk.END, f"Client {self.sockname} disconnected\n")
                    self.client_socket.close()
                    self.server.remove_connection(self)
                    break
        except ConnectionResetError:
            self.server.log_area.insert(tk.END, f"Connection with {self.sockname} lost\n")
        except Exception as e:
            self.server.log_area.insert(tk.END, f"Error receiving message from {self.sockname}: {str(e)}\n")
        finally:
            self.client_socket.close()
            self.server.remove_connection(self)


class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Chat Server")
        self.allowed_ips = []

        # Create the input area for allowed IPs
        frame = ttk.Frame(root, padding="10 10 10 10")
        frame.grid(row=0, column=0, sticky="nsew")

        self.ip_label = ttk.Label(frame, text="Enter allowed IPs:")
        self.ip_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        self.ip_entry = ttk.Entry(frame, width=30)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)

        self.add_ip_button = ttk.Button(frame, text="Add IP", command=self.add_ip)
        self.add_ip_button.grid(row=1, column=1, padx=5, pady=5, sticky=tk.E)

        self.start_button = ttk.Button(frame, text="Start Server", command=self.start_server)
        self.start_button.grid(row=2, column=1, padx=5, pady=10, sticky=tk.E)

        # Add a text area to display logs
        self.log_area = scrolledtext.ScrolledText(frame, height=10, width=50, state=tk.DISABLED)
        self.log_area.grid(row=3, column=0, columnspan=2, padx=5, pady=10)

        # Scrollbar for the text area
        self.scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_area.yview)
        self.scrollbar.grid(row=3, column=2, sticky='ns')
        self.log_area['yscrollcommand'] = self.scrollbar.set

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def add_ip(self):
        ip = self.ip_entry.get()
        if ip:
            self.allowed_ips.append(ip)
            self.log_area.config(state=tk.NORMAL)
            self.log_area.insert(tk.END, f"Added IP: {ip}\n")
            self.log_area.config(state=tk.DISABLED)
            self.ip_entry.delete(0, tk.END)

    def start_server(self):
        if not self.allowed_ips:
            messagebox.showerror("Error", "No IPs added. Cannot start the server.")
            return
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, "Starting server...\n")
        self.log_area.config(state=tk.DISABLED)
        server = Server("localhost", 8080, self.allowed_ips, self.log_area)
        server.start()


# Create the main application window
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nServer application closed by user.")
