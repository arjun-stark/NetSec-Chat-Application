import os
import json
import time
import socket
import threading
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import argon2

# Configuration
CONFIG_FILE = "client_config.json"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000
BUFFER_SIZE = 4096

class SecureMessengerClient:
    def __init__(self):
        self.load_config()
        self.username = None
        self.session_keys = {}
        self.peer_connections = {}
        self.server_public_key = self.load_server_public_key()
        self.ephemeral_key_pair = None
        self.server_socket = None
        self.running = False
        
    def load_config(self):
        """Load client configuration from file"""
        try:
            with open(CONFIG_FILE) as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print("Configuration file not found. Using defaults.")
            self.config = {
                "server_host": SERVER_HOST,
                "server_port": SERVER_PORT
            }
    
    def load_server_public_key(self):
        """Load the server's pre-trusted public key"""
        # In a real implementation, this would load from a secure storage
        # For demo purposes, we'll generate one
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        return private_key.public_key()
    
    def generate_ephemeral_key_pair(self):
        """Generate new ephemeral ECDH key pair"""
        self.ephemeral_key_pair = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        return self.ephemeral_key_pair.public_key()
    
    def derive_shared_key(self, peer_public_key):
        """Derive shared secret using ECDH"""
        shared_key = self.ephemeral_key_pair.exchange(ec.ECDH(), peer_public_key)
        return self.derive_session_key(shared_key)
    
    def derive_session_key(self, shared_secret):
        """Derive session key using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'session_key',
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
    
    def encrypt_message(self, message, key):
        """Encrypt message using AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
        return nonce + ciphertext
    
    def decrypt_message(self, ciphertext, key):
        """Decrypt message using AES-GCM"""
        aesgcm = AESGCM(key)
        nonce = ciphertext[:12]
        ciphertext = ciphertext[12:]
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    
    def authenticate_with_server(self):
        """Implement PAKE-based authentication with server"""
        print("=== Authentication ===")
        username = input("Username: ")
        password = getpass("Password: ")
        
        # Generate SRP verifier (would be done during registration)
        salt = os.urandom(16)
        verifier = argon2.hash_password(password.encode(), salt)
        
        # Generate ephemeral keys for authentication
        a_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        a_public = a_private.public_key()
        
        # Send authentication request to server
        auth_request = {
            "username": username,
            "a_public": a_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        
        # In real implementation, would send to server and get response
        # For demo, we'll simulate successful authentication
        print("Authenticating...")
        time.sleep(1)  # Simulate network delay
        
        # Simulate server response with ephemeral key
        b_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        b_public = b_private.public_key()
        
        # Derive session key
        shared_secret = a_private.exchange(ec.ECDH(), b_public)
        session_key = self.derive_session_key(shared_secret)
        
        # Store session information
        self.username = username
        self.session_keys["server"] = session_key
        print("Authentication successful!")
        
        # Start peer listener
        self.start_peer_listener()
        
        return True
    
    def start_peer_listener(self):
        """Start listening for peer connections"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', 0))  # Bind to any available port
        self.server_socket.listen(5)
        self.listener_port = self.server_socket.getsockname()[1]
        
        # Register with server (in real implementation)
        print(f"Listening for peer connections on port {self.listener_port}")
        
        # Start listener thread
        self.running = True
        listener_thread = threading.Thread(target=self.handle_peer_connections)
        listener_thread.daemon = True
        listener_thread.start()
    
    def handle_peer_connections(self):
        """Handle incoming peer connections"""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_peer, args=(conn, addr)).start()
            except:
                if self.running:
                    print("Peer listener error")
                break
    
    def handle_peer(self, conn, addr):
        """Handle communication with a peer"""
        try:
            # Perform key exchange
            peer_public_key_pem = conn.recv(BUFFER_SIZE)
            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem,
                backend=default_backend()
            )
            
            # Send our public key
            our_public_key = self.ephemeral_key_pair.public_key()
            conn.send(our_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            # Derive shared key
            shared_key = self.derive_shared_key(peer_public_key)
            
            # Store peer connection
            peer_id = f"{addr[0]}:{addr[1]}"
            self.peer_connections[peer_id] = {
                "conn": conn,
                "key": shared_key
            }
            
            # Start receiving messages
            while self.running:
                encrypted_msg = conn.recv(BUFFER_SIZE)
                if not encrypted_msg:
                    break
                
                try:
                    message = self.decrypt_message(encrypted_msg, shared_key)
                    print(f"\n[Message from {peer_id}]: {message}")
                except Exception as e:
                    print(f"Decryption error: {e}")
                    break
                    
        except Exception as e:
            print(f"Peer connection error: {e}")
        finally:
            conn.close()
            if peer_id in self.peer_connections:
                del self.peer_connections[peer_id]
    
    def connect_to_peer(self, peer_address):
        """Connect to another peer"""
        try:
            host, port = peer_address.split(":")
            port = int(port)
            
            # Create new socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            
            # Send our public key
            our_public_key = self.ephemeral_key_pair.public_key()
            sock.send(our_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            # Receive peer's public key
            peer_public_key_pem = sock.recv(BUFFER_SIZE)
            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem,
                backend=default_backend()
            )
            
            # Derive shared key
            shared_key = self.derive_shared_key(peer_public_key)
            
            # Store peer connection
            self.peer_connections[peer_address] = {
                "conn": sock,
                "key": shared_key
            }
            
            print(f"Connected to peer {peer_address}")
            return True
            
        except Exception as e:
            print(f"Failed to connect to peer: {e}")
            return False
    
    def send_message(self, peer_id, message):
        """Send encrypted message to peer"""
        if peer_id not in self.peer_connections:
            print(f"No connection to peer {peer_id}")
            return False
            
        try:
            encrypted_msg = self.encrypt_message(message, self.peer_connections[peer_id]["key"])
            self.peer_connections[peer_id]["conn"].send(encrypted_msg)
            return True
        except Exception as e:
            print(f"Failed to send message: {e}")
            return False
    
    def command_interface(self):
        """Main command interface"""
        print("Secure Messenger - Type 'help' for commands")
        
        while True:
            try:
                cmd = input("> ").strip().split()
                if not cmd:
                    continue
                    
                if cmd[0] == "help":
                    print("Commands:")
                    print("  list - Show available peers")
                    print("  connect <ip:port> - Connect to peer")
                    print("  send <peer_id> <message> - Send message")
                    print("  quit - Exit program")
                    
                elif cmd[0] == "list":
                    print("Connected peers:")
                    for peer_id in self.peer_connections:
                        print(f"  {peer_id}")
                        
                elif cmd[0] == "connect" and len(cmd) > 1:
                    self.connect_to_peer(cmd[1])
                    
                elif cmd[0] == "send" and len(cmd) > 2:
                    peer_id = cmd[1]
                    message = " ".join(cmd[2:])
                    if self.send_message(peer_id, message):
                        print(f"Message sent to {peer_id}")
                        
                elif cmd[0] == "quit":
                    self.running = False
                    if self.server_socket:
                        self.server_socket.close()
                    print("Goodbye!")
                    break
                    
                else:
                    print("Unknown command")
                    
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    client = SecureMessengerClient()
    if client.authenticate_with_server():
        client.command_interface()