import os
import json
import socket
import threading
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import argon2
import sqlite3
from getpass import getpass

class SecureMessengerServer:
    def __init__(self):
        self.host = "0.0.0.0"
        self.port = 5000
        self.server_socket = None
        self.running = False
        self.clients = {}
        self.setup_database()
        self.generate_server_keys()
        
    def setup_database(self):
        """Initialize the user database"""
        self.conn = sqlite3.connect("secure_messenger.db")
        self.cursor = self.conn.cursor()
        
        # Create tables if they don't exist
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL
            )
        """)
        
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS active_clients (
                username TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                public_key TEXT NOT NULL,
                last_seen REAL NOT NULL
            )
        """)
        
        self.conn.commit()
    
    def generate_server_keys(self):
        """Generate server's long-term key pair"""
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def register_user(self, username, password):
        """Register a new user with the server"""
        salt = os.urandom(16)
        verifier = argon2.hash_password(password.encode(), salt)
        
        try:
            self.cursor.execute(
                "INSERT INTO users VALUES (?, ?, ?)",
                (username, salt, verifier)
            )
            self.conn.commit()
            print(f"User {username} registered successfully!")
            return True
        except sqlite3.IntegrityError:
            print(f"Username {username} already exists")
            return False
    
    def authenticate_user(self, username, a_public_pem):
        """Authenticate a user using PAKE protocol"""
        # Get user record from database
        self.cursor.execute(
            "SELECT salt, verifier FROM users WHERE username = ?",
            (username,)
        )
        result = self.cursor.fetchone()
        
        if not result:
            print(f"User {username} not found")
            return None
            
        salt, stored_verifier = result
        
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
    
    def update_client_status(self, username, ip, port, public_key_pem):
        """Update or add client connection information"""
        current_time = time.time()
        
        self.cursor.execute(
            """INSERT OR REPLACE INTO active_clients 
            VALUES (?, ?, ?, ?, ?)""",
            (username, ip, port, public_key_pem, current_time)
        )
        self.conn.commit()
    
    def get_peer_info(self, username):
        """Get connection info for a peer"""
        self.cursor.execute(
            "SELECT ip, port, public_key FROM active_clients WHERE username = ?",
            (username,)
        )
        return self.cursor.fetchone()
    
    def cleanup_inactive_clients(self):
        """Remove clients that haven't been seen in a while"""
        while self.running:
            time.sleep(60)  # Cleanup every minute
            threshold = time.time() - 300  # 5 minutes
            
            self.cursor.execute(
                "DELETE FROM active_clients WHERE last_seen < ?",
                (threshold,)
            )
            self.conn.commit()
    
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
                
                # Get peer connection info
                peer_info = request.get("peer_info")
                if peer_info:
                    self.update_client_status(
                        username,
                        ip,
                        peer_info["port"],
                        peer_info["public_key"]
                    )
                
                # Handle further client requests
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                        
                    try:
                        request = json.loads(data.decode())
                        
                        if request.get("type") == "get_peer":
                            peer_username = request.get("peer_username")
                            peer_info = self.get_peer_info(peer_username)
                            
                            if peer_info:
                                response = {
                                    "status": "success",
                                    "peer_info": {
                                        "ip": peer_info[0],
                                        "port": peer_info[1],
                                        "public_key": peer_info[2]
                                    }
                                }
                            else:
                                response = {
                                    "status": "error",
                                    "message": "Peer not found"
                                }
                            
                            conn.send(json.dumps(response).encode())
                            
                    except Exception as e:
                        print(f"Error handling client request: {e}")
                        break
                        
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
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_inactive_clients)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        print(f"Server listening on {self.host}:{self.port}")
        
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
            self.conn.close()

def admin_interface(server):
    """Simple admin interface for server management"""
    print("Secure Messenger Server Admin")
    print("Commands: register, status, quit")
    
    while True:
        cmd = input("admin> ").strip().lower()
        
        if cmd == "register":
            username = input("Username: ")
            password = getpass("Password: ")
            server.register_user(username, password)
            
        elif cmd == "status":
            server.cursor.execute("SELECT COUNT(*) FROM active_clients")
            active = server.cursor.fetchone()[0]
            server.cursor.execute("SELECT COUNT(*) FROM users")
            total = server.cursor.fetchone()[0]
            print(f"Active clients: {active}/{total}")
            
        elif cmd == "quit":
            server.running = False
            print("Shutting down server...")
            break
            
        else:
            print("Unknown command")

if __name__ == "__main__":
    server = SecureMessengerServer()
    
    # Start server in a separate thread
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Start admin interface
    admin_interface(server)