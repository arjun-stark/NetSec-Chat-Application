import os
import json
import socket
import threading
import time
import csv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import argon2

class SecureMessengerServer:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 5000
        self.server_socket = None
        self.running = False
        self.verifiers = {}
        self.generate_server_keys()
        self.initialize_verifiers()
        
    def generate_server_keys(self):
        """Generate server's long-term key pair"""
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def initialize_verifiers(self):
        """Initialize with 3 pre-registered users"""
        # Pre-generated salts and verifiers for demo purposes
        self.verifiers = {
            "Alice": {
                "salt": "a1b2c3d4e5f6g7h8".encode(),
                "verifier": argon2.hash_password(b"AlicePassword", "a1b2c3d4e5f6g7h8".encode())
            },
            "Bob": {
                "salt": "i9j0k1l2m3n4o5p6".encode(),
                "verifier": argon2.hash_password(b"BobPassword", "i9j0k1l2m3n4o5p6".encode())
            },
            "Charlie": {
                "salt": "q7r8s9t0u1v2w3x4".encode(),
                "verifier": argon2.hash_password(b"CharliePassword", "q7r8s9t0u1v2w3x4".encode())
            }
        }
        
        # Save to CSV for reference
        with open('verifiers.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerow(['username', 'salt', 'verifier'])
            for username, data in self.verifiers.items():
                writer.writerow([username, data['salt'].hex(), data['verifier'].hex()])
    
    def authenticate_user(self, username, a_public_pem):
        """Authenticate a user using PAKE protocol"""
        if username not in self.verifiers:
            print(f"User {username} not found")
            return None
            
        # Generate server's ephemeral key pair
        b_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
        b_public = b_private.public_key()
        
        # Load client's public key
        try:
            a_public = serialization.load_pem_public_key(
                a_public_pem.encode(),
                backend=default_backend()
            )
        except:
            print("Invalid client public key")
            return None
            
        # In a real PAKE implementation, we would:
        # 1. Verify the client's proof
        # 2. Generate server proof
        # 3. Derive session key
        
        # For this demo, we'll simulate successful authentication
        # and derive a session key
        shared_secret = b_private.exchange(ec.ECDH(), a_public)
        
        # Derive session key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'session_key',
            backend=default_backend()
        )
        session_key = hkdf.derive(shared_secret)
        
        return {
            "b_public": b_public,
            "session_key": session_key
        }
    
    def handle_client(self, conn, addr):
        """Handle communication with a client"""
        try:
            ip, port = addr
            print(f"New connection from {ip}:{port}")
            
            # Receive authentication request
            data = conn.recv(4096)
            if not data:
                return
                
            try:
                request = json.loads(data.decode())
                username = request.get("username")
                a_public_pem = request.get("a_public")
                
                if not username or not a_public_pem:
                    raise ValueError("Invalid request")
                    
                # Authenticate user
                auth_result = self.authenticate_user(username, a_public_pem)
                if not auth_result:
                    conn.close()
                    return
                    
                # Send server response
                b_public_pem = auth_result["b_public"].public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                
                response = {
                    "status": "success",
                    "b_public": b_public_pem,
                    "session_key": auth_result["session_key"].hex()  # For demo only
                }
                
                conn.send(json.dumps(response).encode())
                
            except Exception as e:
                print(f"Error processing client message: {e}")
                
        finally:
            conn.close()
            print(f"Connection closed from {ip}:{port}")
    
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        print(f"Server listening on {self.host}:{self.port}")
        print("Pre-registered users: Alice, Bob, Charlie")
        
        try:
            while self.running:
                conn, addr = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr)
                ).start()
        except KeyboardInterrupt:
            print("Shutting down server...")
        finally:
            self.running = False
            self.server_socket.close()

if __name__ == "__main__":
    server = SecureMessengerServer()
    server.start()
