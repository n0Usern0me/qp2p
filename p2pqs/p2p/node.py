

import threading

import socket

import json

import hashlib

import platform

import time

import queue

import pickle

import os

from typing import Dict, Any, Set, List

from ..crypto.manager import CryptoManager

from ..db.manager import DatabaseManager

from ..http.api import start_api_server

from ..core.config import ConfigManager



class P2PNode:

    """Enhanced P2P Network Node with improved connection management and content validation logging"""

    

    def __init__(self, user_id: str, p2p_port: int = 4000, enable_http: bool = True, api_port: int = 5001):

        self.p2p_port = p2p_port

        self.api_port = 5001  # FIXED to port 5001

        self.enable_http = enable_http

        self.peers: Dict[tuple, socket.socket] = {}

        self.peer_status: Dict[tuple, Dict] = {}  # Track peer connection status

        self.max_peers = 9

        self.reconnect_attempts = 3

        self.heartbeat_interval = 30  # Send heartbeat every 30 seconds

        self.connection_timeout = 120  # Increased timeout to 2 minutes

        

        # Message tracking to prevent loops

        self.processed_messages: Set[str] = set()

        self.message_lock = threading.Lock()

        

        # Content validation tracking

        self.content_log: List[Dict] = []

        self.content_log_lock = threading.Lock()

        

        # Persistent peer list

        self.known_peers: Set[tuple] = set()

        self.peer_file = "known_peers.json"

        self.load_known_peers()

        

        self.config_manager = ConfigManager()

        

        # Initialize crypto and database (same as before)

        security_keys = self.config_manager.config.get("security", {}).get("keys", {})

        falcon_private = None

        dilithium_private = None

        

        if security_keys.get("falcon"):

            try:

                falcon_private = bytes.fromhex(security_keys["falcon"])

            except ValueError:

                print("[CRYPTO] Invalid falcon key in config, generating new one")

                falcon_private = None

                

        if security_keys.get("dilithium"):

            try:

                dilithium_private = bytes.fromhex(security_keys["dilithium"])

            except ValueError:

                print("[CRYPTO] Invalid dilithium key in config, generating new one")

                dilithium_private = None

        

        self.crypto = CryptoManager(

            crypto_id=user_id,

            falcon_private=falcon_private,

            dilithium_private=dilithium_private

        )



        if self.crypto.falcon_private is None:

            self.crypto.generate_falcon_keypair()

        if self.crypto.dilithium_private is None:

            self.crypto.generate_dilithium_keypair()

        

        self.config_manager.update_security_keys(self.crypto)

        

        # Initialize database with cross-platform path

        db_path = self._get_cross_platform_db_path()

        self.database = DatabaseManager(db_path)

        

        platform_info = self._get_platform_info()

        print(f"[INIT] {platform_info['name']} compatibility mode enabled")

        print(f"[INIT] Database path: {db_path}")

        print(f"[INIT] User ID: {user_id}")

        print("[INIT] Enhanced connection management enabled")

        print(f"[INIT] Max peers: {self.max_peers}")

        print(f"[INIT] Heartbeat interval: {self.heartbeat_interval}s")

        print(f"[INIT] Connection timeout: {self.connection_timeout}s")

        

        # Start services

        threading.Thread(target=self.listen_for_peers, daemon=True).start()

        threading.Thread(target=self.heartbeat_manager, daemon=True).start()

        threading.Thread(target=self.auto_reconnect_manager, daemon=True).start()



        # Start HTTP API server

        self.http_server = None

        if enable_http:

            try:

                self.http_server = start_api_server(self, host="127.0.0.1", port=5001, localhost_only=True)

                threading.Thread(target=self.http_server.serve_forever, daemon=True).start()

                print(f"[HTTP] API server started on http://127.0.0.1:5001")

                print("[HTTP] Enhanced crypto tax system with dual confirmation enabled")

                print("[HTTP] Cross-platform Windows/Linux compatibility confirmed")

            except Exception as e:

                print(f"[HTTP] Failed to start API server: {e}")

                self.http_server = None



    def load_known_peers(self):

        """Load known peers from persistent storage"""

        try:

            if os.path.exists(self.peer_file):

                with open(self.peer_file, 'r') as f:

                    peer_data = json.load(f)

                    self.known_peers = {tuple(peer) for peer in peer_data.get('peers', [])}

                print(f"[PEERS] Loaded {len(self.known_peers)} known peers from storage")

            else:

                print("[PEERS] No persistent peer data found")

        except Exception as e:

            print(f"[PEERS] Error loading known peers: {e}")



    def save_known_peers(self):

        """Save known peers to persistent storage"""

        try:

            peer_data = {

                'peers': list(self.known_peers),

                'last_updated': time.time()

            }

            with open(self.peer_file, 'w') as f:

                json.dump(peer_data, f)

            print(f"[PEERS] Saved {len(self.known_peers)} peers to storage")

        except Exception as e:

            print(f"[PEERS] Error saving known peers: {e}")



    def add_known_peer(self, host: str, port: int):

        """Add peer to known peers list"""

        peer_addr = (host, port)

        if peer_addr not in self.known_peers:

            self.known_peers.add(peer_addr)

            self.save_known_peers()

            print(f"[PEERS] Added {host}:{port} to known peers")



    def log_content_validation(self, content: str, site_name: str, signature: str, 

                             is_valid: bool, source_peer: tuple = None):

        """Log content validation results without author_id"""

        with self.content_log_lock:

            log_entry = {

                'timestamp': time.time(),

                'content': content[:100] + "..." if len(content) > 100 else content,

                'site_name': site_name,

                'signature': signature[:16] + "..." if len(signature) > 16 else signature,

                'is_valid': is_valid,

                'source_peer': f"{source_peer[0]}:{source_peer[1]}" if source_peer else "local",

                'validation_time': time.strftime('%Y-%m-%d %H:%M:%S'),

                'date': time.strftime('%Y-%m-%d')  # Only date

            }

            self.content_log.append(log_entry)

            

            # Keep only last 1000 entries

            if len(self.content_log) > 1000:

                self.content_log = self.content_log[-500:]

            

            # Console output without author info

            status = "✓ VALID" if is_valid else "✗ INVALID"

            source = f"from {source_peer[0]}:{source_peer[1]}" if source_peer else "locally"

            print(f"[CONTENT] {status} - '{site_name}' {source}")

            print(f"[CONTENT] Content: {log_entry['content']}")

            if not is_valid:

                print(f"[CONTENT] ⚠ Site signature verification failed")



    def get_content_validation_log(self) -> List[Dict]:

        """Get recent content validation log"""

        with self.content_log_lock:

            return self.content_log.copy()



    def heartbeat_manager(self):

        """Manage heartbeat messages to keep connections alive"""

        while True:

            try:

                time.sleep(self.heartbeat_interval)

                

                current_time = time.time()

                disconnected_peers = []

                

                for peer_addr, peer_socket in list(self.peers.items()):

                    try:

                        # Send heartbeat

                        heartbeat_msg = {

                            "type": "HEARTBEAT",

                            "timestamp": current_time,

                            "user_id": self.crypto.crypto_id

                        }

                        message_data = json.dumps(heartbeat_msg).encode('utf-8') + b"\n"

                        peer_socket.sendall(message_data)

                        

                        # Update peer status

                        if peer_addr not in self.peer_status:

                            self.peer_status[peer_addr] = {}

                        self.peer_status[peer_addr]['last_heartbeat'] = current_time

                        

                    except Exception as e:

                        print(f"[HEARTBEAT] Failed to send to {peer_addr}: {e}")

                        disconnected_peers.append(peer_addr)

                

                # Remove disconnected peers

                for peer_addr in disconnected_peers:

                    self.peers.pop(peer_addr, None)

                    self.peer_status.pop(peer_addr, None)

                    print(f"[HEARTBEAT] Removed dead peer {peer_addr}")

                        

            except Exception as e:

                print(f"[HEARTBEAT] Manager error: {e}")



    def auto_reconnect_manager(self):

        """Automatically reconnect to known peers"""

        while True:

            try:

                time.sleep(60)  # Check every minute

                

                # Reconnect to known peers not currently connected

                for peer_addr in list(self.known_peers):

                    if peer_addr not in self.peers and len(self.peers) < self.max_peers:

                        host, port = peer_addr

                        print(f"[RECONNECT] Attempting to reconnect to {host}:{port}")

                        if self.connect_to_peer(host, port):

                            print(f"[RECONNECT] ✓ Reconnected to {host}:{port}")

                        else:

                            print(f"[RECONNECT] ✗ Failed to reconnect to {host}:{port}")

                        time.sleep(2)  # Brief pause between attempts

                        

            except Exception as e:

                print(f"[RECONNECT] Manager error: {e}")



    def _get_platform_info(self):

        """Get detailed platform information"""

        system = platform.system().lower()

        return {

            "name": platform.system(),

            "version": platform.release(),

            "architecture": platform.machine(),

            "python_version": platform.python_version(),

            "is_windows": system == "windows",

            "is_linux": system == "linux",

            "is_cross_platform": system in ["windows", "linux", "darwin"]

        }



    def _get_cross_platform_db_path(self):

        """Get platform-appropriate database path for Windows/Linux"""

        import os

        import tempfile

        

        platform_info = self._get_platform_info()

        

        # Windows-specific path handling

        if platform_info["is_windows"]:

            try:

                appdata = os.environ.get('LOCALAPPDATA')

                if appdata:

                    db_dir = os.path.join(appdata, "P2PQuantumSafe")

                    os.makedirs(db_dir, exist_ok=True)

                    db_path = os.path.join(db_dir, "p2p_data.db")

                    

                    test_file = os.path.join(db_dir, "test_write.tmp")

                    with open(test_file, 'w') as f:

                        f.write("test")

                    os.remove(test_file)

                    

                    print(f"[DB] Using Windows AppData: {db_path}")

                    return db_path

            except (OSError, PermissionError) as e:

                print(f"[DB] Cannot use Windows AppData: {e}")

        

        # Linux-specific path handling

        elif platform_info["is_linux"]:

            try:

                home_dir = os.path.expanduser("~")

                db_dir = os.path.join(home_dir, ".p2pqs")

                os.makedirs(db_dir, exist_ok=True)

                db_path = os.path.join(db_dir, "p2p_data.db")

                

                test_file = os.path.join(db_dir, "test_write.tmp")

                with open(test_file, 'w') as f:

                    f.write("test")

                os.remove(test_file)

                

                print(f"[DB] Using Linux home directory: {db_path}")

                return db_path

                

            except (OSError, PermissionError) as e:

                print(f"[DB] Cannot use Linux home directory: {e}")

        

        # Fallback to current directory

        try:

            db_path = "./p2p_data.db"

            test_file = "./test_write.tmp"

            with open(test_file, 'w') as f:

                f.write("test")

            os.remove(test_file)

            

            print(f"[DB] Using current directory: {db_path}")

            return db_path

            

        except (OSError, PermissionError) as e:

            print(f"[DB] Cannot use current directory: {e}")

            

        # Last resort: temporary directory

        temp_dir = tempfile.gettempdir()

        db_path = os.path.join(temp_dir, "p2pqs_data.db")

        print(f"[DB] Using temporary directory: {db_path}")

        return db_path



    def _generate_message_id(self, message: Dict[str, Any]) -> str:

        """Generate unique ID for message to prevent loops"""

        content = str(message.get("content", ""))

        site_name = str(message.get("site_name", ""))

        msg_type = str(message.get("type", ""))

        timestamp = str(message.get("timestamp", ""))

        

        combined = f"{msg_type}:{site_name}:{content}:{timestamp}"

        return hashlib.sha256(combined.encode()).hexdigest()[:16]



    def _is_message_processed(self, message_id: str) -> bool:

        """Check if message was already processed"""

        with self.message_lock:

            if message_id in self.processed_messages:

                return True

            

            if len(self.processed_messages) > 1000:

                old_messages = list(self.processed_messages)[:500]

                for old_msg in old_messages:

                    self.processed_messages.discard(old_msg)

            

            self.processed_messages.add(message_id)

            return False



    def _verify_site_content_signature(self, content: str, signature_hex: str, site_name: str) -> bool:

        """Verify content signature specifically against site's public key"""

        try:

            if not signature_hex or not content or not site_name:

                print(f"[VERIFY] Missing signature data for site '{site_name}'")

                return False

            

            site_keys = self.database.get_site_keys(site_name)

            if not site_keys or not site_keys.get("dilithium_public"):

                print(f"[VERIFY] No public key found for site '{site_name}' - requesting from network")

                self._request_site_keys(site_name)

                return False

            

            dilithium_public = bytes.fromhex(site_keys["dilithium_public"])

            signature = bytes.fromhex(signature_hex)

            

            # Verify signature is specifically for this site's content

            is_valid = self.crypto.verify_signature(content, signature, dilithium_public)

            

            if is_valid:

                print(f"[VERIFY] Site signature verification SUCCESS for '{site_name}'")

            else:

                print(f"[VERIFY] Site signature verification FAILED for '{site_name}'")

                print(f"[VERIFY] This content was not properly signed by the site owner")

            

            return is_valid

            

        except Exception as e:

            print(f"[VERIFY] Site signature verification error: {e}")

            return False



    def _request_site_keys(self, site_name: str):

        """Request site keys from peers"""

        key_request_msg = {

            "type": "KEY_REQUEST",

            "site_name": site_name,

            "requester_id": self.crypto.crypto_id,

            "timestamp": time.time()

        }

        self.broadcast_to_peers(key_request_msg)

        print(f"[KEY_REQUEST] Requested keys for site '{site_name}' from network")



    def connect_to_peer(self, host: str, port: int) -> bool:

        """Connect to another P2P node with enhanced retry logic"""

        if len(self.peers) >= self.max_peers:

            print(f"[P2P] Connection limit reached ({self.max_peers})")

            return False

        

        peer_addr = (host, port)

        if peer_addr in self.peers:

            print(f"[P2P] Already connected to {host}:{port}")

            return True

        

        for attempt in range(self.reconnect_attempts):

            try:

                peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                peer_socket.settimeout(15)

                

                print(f"[P2P] Connecting to {host}:{port} (attempt {attempt + 1}/{self.reconnect_attempts})")

                peer_socket.connect((host, port))



                platform_info = self._get_platform_info()

                hello_message = {

                    "type": "HELLO",

                    "version": "2.0",

                    "platform": platform_info["name"],

                    "architecture": platform_info["architecture"],

                    "language": "english",

                    "user_id": self.crypto.crypto_id

                }

                message_data = json.dumps(hello_message).encode() + b"\n"

                peer_socket.sendall(message_data)



                response = peer_socket.recv(1024).decode().strip()

                if response.startswith("WELCOME"):

                    print(f"[P2P] ✓ Connected to {host}:{port}")

                    peer_socket.settimeout(self.connection_timeout)

                    self.peers[peer_addr] = peer_socket

                    self.add_known_peer(host, port)

                    

                    # Initialize peer status

                    self.peer_status[peer_addr] = {

                        'connected_at': time.time(),

                        'last_heartbeat': time.time(),

                        'platform': platform_info["name"]

                    }

                    

                    threading.Thread(

                        target=self._handle_peer_messages, 

                        args=(peer_socket, peer_addr), 

                        daemon=True

                    ).start()

                    

                    # Synchronize sites after connection

                    self._sync_sites_with_peer(peer_addr)

                    

                    return True

                else:

                    print(f"[P2P] Unexpected response from {host}:{port}: {response}")

                    peer_socket.close()

                    

            except socket.timeout:

                print(f"[P2P] Connection timeout to {host}:{port} (attempt {attempt + 1})")

            except ConnectionRefusedError:

                print(f"[P2P] Connection refused by {host}:{port} (attempt {attempt + 1})")

                break  # No point retrying connection refused

            except Exception as e:

                print(f"[P2P] Connection error to {host}:{port} (attempt {attempt + 1}): {e}")

            

            if attempt < self.reconnect_attempts - 1:

                time.sleep(2)  # Wait before retry

        

        return False



    def _sync_sites_with_peer(self, peer_addr):

        """Synchronize sites list with newly connected peer"""

        sync_msg = {

            "type": "SITE_SYNC_REQUEST",

            "requester_id": self.crypto.crypto_id,

            "timestamp": time.time()

        }

        try:

            peer_socket = self.peers.get(peer_addr)

            if peer_socket:

                message_data = json.dumps(sync_msg).encode('utf-8') + b"\n"

                peer_socket.sendall(message_data)

                print(f"[SYNC] Requested site sync from {peer_addr[0]}:{peer_addr[1]}")

        except Exception as e:

            print(f"[SYNC] Failed to request site sync from {peer_addr}: {e}")



    def listen_for_peers(self):

        """Listen for incoming P2P connections with enhanced error handling"""

        try:

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            

            platform_info = self._get_platform_info()

            

            try:

                server_socket.bind(("0.0.0.0", self.p2p_port))

                print(f"[P2P] Server binding successful on port {self.p2p_port}")

            except PermissionError:

                print(f"[P2P] Permission denied for port {self.p2p_port}, trying alternative...")

                self.p2p_port = self.p2p_port + 1000

                server_socket.bind(("0.0.0.0", self.p2p_port))

                print(f"[P2P] Using alternative port: {self.p2p_port}")

            

            server_socket.listen(15)  # Increased backlog

            print(f"[P2P] Server listening on 0.0.0.0:{self.p2p_port} ({platform_info['name']})")



            while True:

                try:

                    client_socket, address = server_socket.accept()

                    print(f"[P2P] Incoming connection from {address}")

                    threading.Thread(

                        target=self._handle_incoming_peer, 

                        args=(client_socket, address), 

                        daemon=True

                    ).start()

                except Exception as e:

                    print(f"[P2P] Accept error: {e}")

                    time.sleep(1)  # Brief pause before continuing

                    

        except Exception as e:

            print(f"[P2P] Server socket error: {e}")



    def _handle_incoming_peer(self, client_socket, address):

        """Handle incoming peer connection with enhanced validation"""

        host, port = address

        try:

            client_socket.settimeout(30)

            data = client_socket.recv(1024).decode().strip()

            

            if not data:

                client_socket.close()

                return



            try:

                hello_data = json.loads(data)

            except json.JSONDecodeError:

                print(f"[P2P] Invalid JSON from {host}:{port}")

                client_socket.close()

                return

            

            if hello_data.get("type") == "HELLO":

                peer_platform = hello_data.get("platform", "unknown")

                peer_language = hello_data.get("language", "unknown")

                peer_user_id = hello_data.get("user_id", "unknown")

                

                if len(self.peers) >= self.max_peers:

                    print(f"[P2P] Connection limit reached, rejecting {host}:{port}")

                    error_msg = "BUSY - Connection limit reached\n"

                    client_socket.sendall(error_msg.encode())

                    client_socket.close()

                    return

                

                welcome_message = f"WELCOME {hello_data.get('version', 'unknown')}\n"

                client_socket.sendall(welcome_message.encode())

                

                client_socket.settimeout(self.connection_timeout)

                peer_addr = (host, port)

                self.peers[peer_addr] = client_socket

                self.add_known_peer(host, port)

                

                # Initialize peer status

                self.peer_status[peer_addr] = {

                    'connected_at': time.time(),

                    'last_heartbeat': time.time(),

                    'platform': peer_platform,

                    'user_id': peer_user_id

                }

                

                print(f"[P2P] ✓ Peer connected: {host}:{port} (Platform: {peer_platform})")

                

                threading.Thread(

                    target=self._handle_peer_messages, 

                    args=(client_socket, peer_addr), 

                    daemon=True

                ).start()

                

                # Synchronize automatically after connection

                self._sync_sites_with_peer(peer_addr)

                

            else:

                print(f"[P2P] Invalid handshake from {host}:{port}")

                client_socket.close()

                

        except Exception as e:

            print(f"[P2P] Error handling incoming peer {host}:{port}: {e}")

            try:

                client_socket.close()

            except:

                pass



    def _handle_peer_messages(self, peer_socket, address):

        """Handle messages from connected peer with improved reliability"""

        host, port = address

        message_buffer = ""

        

        try:            

            while address in self.peers:

                try:

                    data = peer_socket.recv(4096)

                    if not data:

                        print(f"[P2P] No data received from {host}:{port}, disconnecting")

                        break

                    

                    message_buffer += data.decode('utf-8', errors='ignore')

                    

                    # Process complete messages (ended with \n)

                    while '\n' in message_buffer:

                        line, message_buffer = message_buffer.split('\n', 1)

                        line = line.strip()

                        

                        if line:

                            try:

                                message = json.loads(line)

                                self._process_peer_message(message, address)

                            except json.JSONDecodeError as e:

                                print(f"[P2P] JSON decode error from {host}:{port}: {e}")

                                continue

                                

                except socket.timeout:

                    # Check if peer is still responding to heartbeats

                    peer_status = self.peer_status.get(address, {})

                    last_heartbeat = peer_status.get('last_heartbeat', 0)

                    if time.time() - last_heartbeat > self.connection_timeout:

                        print(f"[P2P] Heartbeat timeout with {host}:{port}")

                        break

                    continue

                    

                except UnicodeDecodeError as e:

                    print(f"[P2P] Unicode decode error from {host}:{port}: {e}")

                    continue

                except Exception as e:

                    print(f"[P2P] Message handling error from {host}:{port}: {e}")

                    break

                    

        except Exception as e:

            print(f"[P2P] Connection error with {host}:{port}: {e}")

        finally:

            try:

                peer_socket.close()

            except:

                pass

            self.peers.pop(address, None)

            self.peer_status.pop(address, None)

            print(f"[P2P] ✗ Disconnected from {host}:{port}")



    def _process_peer_message(self, message: Dict[str, Any], sender_address):

        """Process received message from peer with enhanced logging"""

        message_type = message.get("type")

        

        # Handle heartbeat responses

        if message_type == "HEARTBEAT":

            peer_user_id = message.get("user_id", "unknown")

            if sender_address in self.peer_status:

                self.peer_status[sender_address]['last_heartbeat'] = time.time()

                self.peer_status[sender_address]['user_id'] = peer_user_id

            return

        

        # Check for message loops

        message_id = self._generate_message_id(message)

        if self._is_message_processed(message_id):

            return

        

        if message_type == "SYNC_REQUEST":

            self._handle_sync_request(message, sender_address)

        elif message_type == "SYNC_RESPONSE":

            self._handle_sync_response(message, sender_address)

        elif message_type == "CONTENT_BROADCAST":

            self._handle_content_broadcast(message, sender_address)

        elif message_type == "KEY_REQUEST":

            self._handle_key_request(message, sender_address)

        elif message_type == "KEY_RESPONSE":

            self._handle_key_response(message, sender_address)

        elif message_type == "SITE_SYNC_REQUEST":

            self._handle_site_sync_request(message, sender_address)

        elif message_type == "SITE_SYNC_RESPONSE":

            self._handle_site_sync_response(message, sender_address)



    def _handle_key_request(self, message: Dict[str, Any], sender_address):

        """Handle site key request from peer"""

        site_name = message.get("site_name")

        requester_id = message.get("requester_id")

        

        if not site_name:

            return

        

        site_keys = self.database.get_site_keys(site_name)

        if site_keys and site_keys.get("dilithium_public"):

            # Send only public keys for site signature verification

            key_response = {

                "type": "KEY_RESPONSE",

                "site_name": site_name,

                "falcon_public": site_keys.get("falcon_public"),

                "dilithium_public": site_keys.get("dilithium_public"),

                "provider_id": self.crypto.crypto_id,

                "timestamp": time.time()

            }

            

            try:

                peer_socket = self.peers.get(sender_address)

                if peer_socket:

                    message_data = json.dumps(key_response).encode('utf-8') + b"\n"

                    peer_socket.sendall(message_data)

                    print(f"[KEY_RESPONSE] Sent public keys for site '{site_name}' to {sender_address[0]}:{sender_address[1]}")

            except Exception as e:

                print(f"[KEY_RESPONSE] Failed to send keys: {e}")



    def _handle_key_response(self, message: Dict[str, Any], sender_address):

        """Handle site key response from peer"""

        site_name = message.get("site_name")

        falcon_public = message.get("falcon_public")

        dilithium_public = message.get("dilithium_public")

        provider_id = message.get("provider_id")

        

        if not site_name or not dilithium_public:

            return

        

        # Store the public keys for site signature verification

        try:

            keys_data = {

                "falcon_public": falcon_public,

                "dilithium_public": dilithium_public

            }

            

            success = self.database.store_site_public_keys(site_name, keys_data)

            if success:

                print(f"[KEY_RESPONSE] Stored public keys for site '{site_name}' from {sender_address[0]}:{sender_address[1]}")

                print(f"[KEY_RESPONSE] Can now verify signatures from site '{site_name}'")

            else:

                print(f"[KEY_RESPONSE] Failed to store keys for site '{site_name}'")

                

        except Exception as e:

            print(f"[KEY_RESPONSE] Error storing keys: {e}")



    def _handle_site_sync_request(self, message: Dict[str, Any], sender_address):

        """Handle site synchronization request"""

        requester_id = message.get("requester_id")

        

        try:

            sites = self.database.get_sites()

            public_sites = []

            

            for site in sites:

                # Send only public information about sites

                public_site = {

                    "site_name": site.get("site_name"),

                    "created_date": site.get("created_date"),

                    "falcon_public": site.get("falcon_public"),

                    "dilithium_public": site.get("dilithium_public")

                }

                public_sites.append(public_site)

            

            sync_response = {

                "type": "SITE_SYNC_RESPONSE",

                "sites": public_sites,

                "provider_id": self.crypto.crypto_id,

                "timestamp": time.time()

            }

            

            peer_socket = self.peers.get(sender_address)

            if peer_socket:

                message_data = json.dumps(sync_response).encode('utf-8') + b"\n"

                peer_socket.sendall(message_data)

                print(f"[SITE_SYNC] Sent {len(public_sites)} sites to {sender_address[0]}:{sender_address[1]}")

                

        except Exception as e:

            print(f"[SITE_SYNC] Error handling sync request: {e}")



    def _handle_site_sync_response(self, message: Dict[str, Any], sender_address):

        """Handle site synchronization response"""

        sites = message.get("sites", [])

        provider_id = message.get("provider_id")

        

        if not sites:

            return

        

        stored_count = 0

        for site_data in sites:

            site_name = site_data.get("site_name")

            if not site_name:

                continue

            

            # Store public site information for signature verification

            try:

                keys_data = {

                    "falcon_public": site_data.get("falcon_public"),

                    "dilithium_public": site_data.get("dilithium_public")

                }

                

                if keys_data["dilithium_public"]:  # Only store if we have the signature key

                    success = self.database.store_site_public_keys(site_name, keys_data)

                    if success:

                        stored_count += 1

                        

            except Exception as e:

                print(f"[SITE_SYNC] Error storing site '{site_name}': {e}")

        

        print(f"[SITE_SYNC] Received and stored {stored_count} sites from {sender_address[0]}:{sender_address[1]}")



    def _handle_sync_request(self, message: Dict[str, Any], sender_address):

        """Handle content sync request from peer"""

        site_name = message.get("site_name")

        

        if not site_name:

            return

        

        try:

            # Get content for the requested site

            contents = self.database.get_content(site_name=site_name, limit=100)

            

            sync_response = {

                "type": "SYNC_RESPONSE",

                "site_name": site_name,

                "contents": contents,

                "provider_id": self.crypto.crypto_id,

                "timestamp": time.time()

            }

            

            peer_socket = self.peers.get(sender_address)

            if peer_socket:

                message_data = json.dumps(sync_response).encode('utf-8') + b"\n"

                peer_socket.sendall(message_data)

                print(f"[SYNC] Sent {len(contents)} content items for '{site_name}' to {sender_address[0]}:{sender_address[1]}")

                

        except Exception as e:

            print(f"[SYNC] Error handling sync request: {e}")



    def _handle_sync_response(self, message: Dict[str, Any], sender_address):

        """Handle content sync response from peer"""

        site_name = message.get("site_name")

        contents = message.get("contents", [])

        provider_id = message.get("provider_id")

        

        if not site_name or not contents:

            return

        

        stored_count = 0

        for content_data in contents:

            content = content_data.get("content")

            signature = content_data.get("signature")

            

            if not content:

                continue

            

            # Verify signature against site's public key

            is_valid = True

            if signature:

                is_valid = self._verify_site_content_signature(content, signature, site_name)

            

            self.log_content_validation(content, site_name, signature or "", is_valid, sender_address)

            

            if is_valid:

                try:

                    success = self.database.store_content(

                        site_name=site_name,

                        content=content,

                        author_id="network_sync",  # Internal marker, not displayed

                        signature=signature or "",

                        encrypted_data=b''

                    )

                    if success:

                        stored_count += 1

                except Exception as e:

                    print(f"[SYNC] Error storing content: {e}")

        

        print(f"[SYNC] Stored {stored_count} valid content items from {sender_address[0]}:{sender_address[1]}")



    def _handle_content_broadcast(self, message: Dict[str, Any], sender_address):

        """Handle content broadcast with site signature verification"""

        site_name = message.get("site_name")

        content = message.get("content")

        signature = message.get("signature")

        

        if not all([site_name, content]):

            print(f"[CONTENT] ✗ Incomplete content from {sender_address}")

            return

        

        # Verify signature is from the site owner, not just any node

        is_valid = False

        if signature:

            is_valid = self._verify_site_content_signature(content, signature, site_name)

            if not is_valid:

                # If we don't have the site's public keys, try to get them

                site_keys = self.database.get_site_keys(site_name)

                if not site_keys or not site_keys.get("dilithium_public"):

                    print(f"[CONTENT] Requesting public keys for unknown site '{site_name}'")

                    self._request_site_keys(site_name)

        else:

            print(f"[CONTENT] ✗ No signature provided for content from {sender_address}")

        

        # Log validation result without author info

        self.log_content_validation(content, site_name, signature or "", is_valid, sender_address)

        

        if is_valid:

            # Store valid content that's properly signed by the site

            try:

                success = self.database.store_content(

                    site_name=site_name,

                    content=content,

                    author_id="network_peer",  # Internal marker, not displayed

                    signature=signature,

                    encrypted_data=b''

                )

                

                if success:

                    print(f"[CONTENT] ✓ Stored site-verified content for '{site_name}'")

                    # Forward to other peers

                    self._forward_to_other_peers(message, sender_address)

                else:

                    print(f"[CONTENT] ✗ Failed to store content for site '{site_name}'")

            except Exception as e:

                print(f"[CONTENT] ✗ Error storing content: {e}")

        else:

            print(f"[CONTENT] ✗ Rejected invalid site signature for '{site_name}'")



    def _forward_to_other_peers(self, message: Dict[str, Any], exclude_address):

        """Forward verified message to other peers"""

        try:

            message_data = json.dumps(message).encode('utf-8') + b"\n"

        except UnicodeEncodeError as e:

            print(f"[P2P] Unicode encode error: {e}")

            return

            

        forwarded_count = 0

        failed_peers = []

        

        for peer_address, peer_socket in list(self.peers.items()):

            if peer_address == exclude_address:

                continue

                

            try:

                peer_socket.sendall(message_data)

                forwarded_count += 1

            except Exception as e:

                print(f"[P2P] Error forwarding to {peer_address}: {e}")

                failed_peers.append(peer_address)

        

        # Remove failed peers

        for peer_addr in failed_peers:

            self.peers.pop(peer_addr, None)

            self.peer_status.pop(peer_addr, None)

        

        print(f"[FORWARD] Message forwarded to {forwarded_count} peers")



    def broadcast_content_to_network(self, site_name: str, content: str) -> bool:

        """Broadcast content with proper site signature"""

        try:

            # Verify we own this site and get the keys

            keys = self.database.get_site_keys(site_name)

            if not keys:

                print(f"[BROADCAST] ✗ Site '{site_name}' not found or not owned")

                return False

            

            # Sign with the site's private key

            dilithium_private = bytes.fromhex(keys["dilithium_private"])

            signature = self.crypto.sign_data(content, dilithium_private)

            

            # Store locally first

            success = self.database.store_content(

                site_name=site_name,

                content=content,

                author_id="local_owner",  # Internal marker, not displayed

                encrypted_data=b'',

                signature=signature.hex()

            )

            

            if not success:

                print(f"[BROADCAST] ✗ Failed to store content locally")

                return False

            

            # Log local validation

            self.log_content_validation(content, site_name, signature.hex(), True, None)

            

            # Create broadcast message

            broadcast_msg = {

                "type": "CONTENT_BROADCAST",

                "site_name": site_name,

                "content": content,

                "signature": signature.hex(),  # Site signature, not node signature

                "timestamp": time.time()

            }

            

            # Broadcast to all peers

            self.broadcast_to_peers(broadcast_msg)

            

            peer_count = len(self.peers)

            print(f"[BROADCAST] ✓ Site content broadcast to {peer_count} peers")

            print(f"[BROADCAST] Site: {site_name}")

            print(f"[BROADCAST] Content: {content[:100]}{'...' if len(content) > 100 else ''}")

            print(f"[BROADCAST] Signed with site's private key for verification")

            

            return True

            

        except Exception as e:

            print(f"[BROADCAST] ✗ Error: {e}")

            return False



    def get_peer_count(self) -> int:

        """Get current number of connected peers"""

        return len(self.peers)



    def get_peer_list(self) -> List[tuple]:

        """Get list of connected peer addresses"""

        return list(self.peers.keys())



    def get_peer_status_info(self) -> Dict:

        """Get detailed peer status information"""

        status_info = {}

        current_time = time.time()

        

        for peer_addr, status in self.peer_status.items():

            connected_duration = current_time - status.get('connected_at', current_time)

            last_heartbeat_ago = current_time - status.get('last_heartbeat', current_time)

            

            status_info[f"{peer_addr[0]}:{peer_addr[1]}"] = {

                'platform': status.get('platform', 'unknown'),

                'user_id': status.get('user_id', 'unknown'),

                'connected_duration': f"{connected_duration:.0f}s",

                'last_heartbeat': f"{last_heartbeat_ago:.0f}s ago",

                'is_alive': last_heartbeat_ago < 60

            }

        

        return status_info



    def broadcast_to_peers(self, message: Dict[str, Any]):

        """Broadcast message to all connected peers"""

        try:

            message_data = json.dumps(message).encode('utf-8') + b"\n"

        except UnicodeEncodeError as e:

            print(f"[BROADCAST] Unicode encode error: {e}")

            return

            

        successful_broadcasts = 0

        failed_peers = []

        

        for peer_address, peer_socket in list(self.peers.items()):

            try:

                peer_socket.sendall(message_data)

                successful_broadcasts += 1

            except Exception as e:

                print(f"[BROADCAST] Error sending to {peer_address}: {e}")

                failed_peers.append(peer_address)

        

        # Clean up failed peers

        for peer_addr in failed_peers:

            self.peers.pop(peer_addr, None)

            self.peer_status.pop(peer_addr, None)

        

        print(f"[BROADCAST] Message sent to {successful_broadcasts}/{len(self.peers)} peers")



    def shutdown(self):

        """Gracefully shutdown the node"""

        print("[SHUTDOWN] Closing peer connections...")

        

        # Send goodbye message to all peers

        goodbye_msg = {

            "type": "GOODBYE",

            "user_id": self.crypto.crypto_id,

            "reason": "Node shutdown"

        }

        self.broadcast_to_peers(goodbye_msg)

        

        # Close all peer connections

        for peer_socket in self.peers.values():

            try:

                peer_socket.close()

            except:

                pass

        

        # Save known peers

        self.save_known_peers()

        

        # Stop HTTP server

        if self.http_server:

            self.http_server.shutdown()

        

        print("[SHUTDOWN] Node shutdown complete")

 