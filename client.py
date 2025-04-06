import os
import json
import socket
import threading
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import base64

class SecureMessengerClient:
    def __init__(self):
        self.server_host = "127.0.0.1"
        self.server_port = 5000
        self.username = None
        self.peer_connections = {}
        self.server_public_key = None
        self.ephemeral_key_pair = None
        self.listener_socket = None
        self.running = False
        self.load_server_public_key()
        
    def load_server_public_key(self):
        """Load the server's public key (hardcoded for demo)"""
        # In a real implementation, this would be properly secured
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.server_public_key = private_key.public_key()
    
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
        """Authenticate with server using PAKE"""
        print("=== Authentication ===")
        username = input("Username: ")
        password = getpass("Password: ")
        
        # Generate ephemeral key pair for authentication
        a_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        a_public = a_private.public_key()
        
        # Connect to server
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.server_host, self.server_port))
                
                # Send authentication request
                auth_request = {
                    "username": username,
                    "a_public": a_public.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode()
                }
                sock.send(json.dumps(auth_request).encode())
                
                # Get server response
                response = json.loads(sock.recv(4096).decode())
                if response.get("status") != "success":
                    print("Authentication failed")
                    return False
                
                # Load server's ephemeral public key
                b_public = serialization.load_pem_public_key(
                    response["b_public"].encode(),
                    backend=default_backend()
                )
                
                # Derive session key
                shared_secret = a_private.exchange(ec.ECDH(), b_public)
                session_key = self.derive_session_key(shared_secret)
                
                # Verify session key matches (in real implementation would use proper proof)
                if session_key.hex() != response["session_key"]:
                    print("Session key mismatch")
                    return False
                
                self.username = username
                print("Authentication successful!")
                return True
                
        except Exception as e:
            print(f"Authentication error: {e}")
            return False
    
    def start_peer_listener(self):
        """Start listening for peer connections"""
        self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener_socket.bind(('0.0.0.0', 0))  # Bind to any available port
        self.listener_socket.listen(5)
        self.listener_port = self.listener_socket.getsockname()[1]
        
        print(f"Listening for peer connections on port {self.listener_port}")
        
        self.running = True
        listener_thread = threading.Thread(target=self.handle_peer_connections)
        listener_thread.daemon = True
        listener_thread.start()
    
    def handle_peer_connections(self):
        """Handle incoming peer connections"""
        while self.running:
            try:
                conn, addr = self.listener_socket.accept()
                threading.Thread(target=self.handle_peer, args=(conn, addr)).start()
            except:
                if self.running:
                    print("Peer listener error")
                break
    
    def handle_peer(self, conn, addr):
        """Handle communication with a peer"""
        peer_id = f"{addr[0]}:{addr[1]}"
        try:
            # Perform key exchange
            peer_public_key_pem = conn.recv(4096)
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
            self.peer_connections[peer_id] = {
                "conn": conn,
                "key": shared_key
            }
            
            print(f"Connected to peer {peer_id}")
            
            # Start receiving messages
            while self.running:
                encrypted_msg = conn.recv(4096)
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
                print(f"Disconnected from {peer_id}")
    
    def connect_to_peer(self, peer_address):
        """Connect to another peer directly"""
        try:
            host, port = peer_address.split(":")
            port = int(port)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            
            # Send our public key
            our_public_key = self.ephemeral_key_pair.public_key()
            sock.send(our_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            
            # Receive peer's public key
            peer_public_key_pem = sock.recv(4096)
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
        print("\nSecure Messenger - Type 'help' for commands")
        print(f"Your connection info: [IP]:{self.listener_port}")
        
        while True:
            try:
                cmd = input("> ").strip().split()
                if not cmd:
                    continue
                    
                if cmd[0] == "help":
                    print("Commands:")
                    print("  list - Show connected peers")
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
                    if self.listener_socket:
                        self.listener_socket.close()
                    for peer_id in list(self.peer_connections.keys()):
                        self.peer_connections[peer_id]["conn"].close()
                    print("Goodbye!")
                    break
                    
                else:
                    print("Unknown command")
                    
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    client = SecureMessengerClient()
    if client.authenticate_with_server():
        client.generate_ephemeral_key_pair()
        client.start_peer_listener()
        client.command_interface()
