


from http.server import HTTPServer, BaseHTTPRequestHandler

from urllib.parse import parse_qs, urlparse

import json

import datetime

import traceback

import time



class APIHandler(BaseHTTPRequestHandler):

   

    p2p_node = None

    

    @classmethod

    def set_p2p_node(cls, node):

        """Set P2P node for all handlers"""

        cls.p2p_node = node



    def _is_localhost(self):

        """Verify request comes from localhost"""

        client_ip = self._get_client_ip()

        localhost_ips = ['127.0.0.1', '::1', '::ffff:127.0.0.1', 'localhost']

        return client_ip in localhost_ips



    def _send_cors_headers(self):

        """Send CORS headers for localhost"""

        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

        self.send_header("Access-Control-Allow-Origin", "*")

        self.send_header("Access-Control-Allow-Credentials", "false")



    def _send_json_response(self, data, status_code=200):

        """Send JSON response"""

        try:

            self.send_response(status_code)

            self._send_cors_headers()

            self.send_header("Content-Type", "application/json; charset=utf-8")

            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")

            self.end_headers()

            

            if isinstance(data, dict) or isinstance(data, list):

                response = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')

            else:

                response = str(data).encode('utf-8')

            

            self.wfile.write(response)

        except Exception as e:

            print(f"[API] Response send error: {e}")



    def _get_client_ip(self):

        """Get client IP address"""

        forwarded = self.headers.get('X-Forwarded-For')

        if forwarded:

            return forwarded.split(',')[0].strip()

        return self.client_address[0]



    def _check_access(self):

        """Check localhost access"""

        client_ip = self._get_client_ip()

        

        if not self._is_localhost():

            print(f"[API] Access denied from {client_ip} - localhost only")

            self._send_json_response({"error": "Access denied - localhost only"}, 403)

            return False

        

        return True



    def log_message(self, format, *args):

        """Simplified logging"""

        print(f"[API] {format % args}")



    def do_OPTIONS(self):

        """Handle CORS preflight requests"""

        if not self._is_localhost():

            self.send_response(403)

            self.end_headers()

            return

        

        self.send_response(200)

        self._send_cors_headers()

        self.end_headers()



    def do_GET(self):

        """Handle GET requests with enhanced endpoints"""

        if not self._check_access():

            return



        parsed_url = urlparse(self.path)

        path = parsed_url.path

        query_params = parse_qs(parsed_url.query)



        print(f"[API] GET {path}")



        try:

            if path == "/api/status":

                self._handle_status()

            elif path == "/api/sites":

                self._handle_get_sites()

            elif path == "/api/userid":

                self._handle_get_userid()

            elif path == "/api/site_keys":

                site_name = query_params.get("site", [None])[0]

                self._handle_get_site_keys(site_name)

            elif path == "/api/content":

                site_name = query_params.get("site", [None])[0]

                author = query_params.get("author", [None])[0]

                self._handle_get_content(site_name, author)

            elif path == "/api/peers":

                self._handle_get_peers()

            elif path == "/api/peer_status":

                self._handle_get_peer_status()

            elif path == "/api/content_validation_log":

                limit = int(query_params.get("limit", [50])[0])

                valid_only = query_params.get("valid_only", ["false"])[0].lower() == "true"

                invalid_only = query_params.get("invalid_only", ["false"])[0].lower() == "true"

                self._handle_content_validation_log(limit, valid_only, invalid_only)

            elif path == "/api/network_stats":

                self._handle_network_stats()

            elif path == "/api/known_peers":

                self._handle_known_peers()

            elif path == "/" or path == "/api":

                self._send_json_response({

                    "status": "P2P API Running - Enhanced Edition", 

                    "version": "2.1",

                    "features": ["content_validation", "auto_reconnect", "extended_timeouts", "heartbeat_system"],

                    "endpoints": [

                        "/api/status", "/api/sites", "/api/userid", "/api/site_keys", 

                        "/api/content", "/api/peers", "/api/peer_status", 

                        "/api/content_validation_log", "/api/network_stats", "/api/known_peers"

                    ]

                })

            else:

                self._send_json_response({"error": f"Endpoint not found: {path}"}, 404)

        except Exception as e:

            print(f"[API] GET error on {path}: {e}")

            traceback.print_exc()

            self._send_json_response({"error": f"Internal server error: {str(e)}"}, 500)



    def do_POST(self):

        """Handle POST requests"""

        if not self._check_access():

            return



        parsed_url = urlparse(self.path)

        path = parsed_url.path



        content_length = int(self.headers.get("Content-Length", 0))

        body = "{}"

        

        if content_length > 0:

            try:

                body = self.rfile.read(content_length).decode('utf-8')

            except Exception as e:

                print(f"[API] Body read error: {e}")

                self._send_json_response({"error": "Data read error"}, 400)

                return

        

        try:

            data = json.loads(body)

        except Exception as e:

            print(f"[API] JSON error: {e}")

            self._send_json_response({"error": "Invalid JSON"}, 400)

            return



        print(f"[API] POST {path}")



        try:

            if path in ["/api/create_site", "/api/sites/register"]:

                self._handle_create_site(data)

            elif path == "/api/content":

                self._handle_post_content(data)

            elif path == "/api/crypto_transaction":

                self._handle_crypto_transaction(data)

            elif path == "/api/connect_peer":

                self._handle_connect_peer(data)

            elif path == "/api/broadcast_content":

                self._handle_broadcast_content(data)

            else:

                self._send_json_response({"error": f"Endpoint not found: {path}"}, 404)

        except Exception as e:

            print(f"[API] POST error on {path}: {e}")

            traceback.print_exc()

            self._send_json_response({"error": f"Internal server error: {str(e)}"}, 500)



    def _handle_status(self):

        """Handle enhanced status request"""

        try:

            if not self.p2p_node:

                self._send_json_response({

                    "error": "P2P node not initialized",

                    "user_id": "unknown",

                    "sites": 0,

                    "contents": 0,

                    "peers": 0,

                    "version": "2.1"

                }, 500)

                return



            user_id = "unknown"

            sites_count = 0

            contents_count = 0

            peers_count = 0

            known_peers_count = 0

            content_log_count = 0

            valid_content_count = 0

            invalid_content_count = 0



            try:

                if hasattr(self.p2p_node, 'crypto') and self.p2p_node.crypto:

                    user_id = getattr(self.p2p_node.crypto, 'crypto_id', 'unknown')

            except:

                pass



            try:

                if hasattr(self.p2p_node, 'database') and self.p2p_node.database:

                    sites = self.p2p_node.database.get_sites()

                    sites_count = len(sites) if sites else 0

                    

                    contents = self.p2p_node.database.get_content(limit=10000)

                    contents_count = len(contents) if contents else 0

            except Exception as e:

                print(f"[API] Database access error: {e}")



            try:

                peers_count = len(getattr(self.p2p_node, "peers", {}))

                known_peers_count = len(getattr(self.p2p_node, "known_peers", set()))

            except:

                pass



            try:

                if hasattr(self.p2p_node, 'get_content_validation_log'):

                    content_log = self.p2p_node.get_content_validation_log()

                    content_log_count = len(content_log)

                    valid_content_count = len([c for c in content_log if c['is_valid']])

                    invalid_content_count = len([c for c in content_log if not c['is_valid']])

            except:

                pass

            

            status = {

                "user_id": user_id,

                "sites": sites_count,

                "contents": contents_count,

                "peers_connected": peers_count,

                "peers_known": known_peers_count,

                "max_peers": getattr(self.p2p_node, 'max_peers', 9),

                "content_log_entries": content_log_count,

                "valid_content_received": valid_content_count,

                "invalid_content_rejected": invalid_content_count,

                "version": "2.1",

                "features": {

                    "auto_reconnect": True,

                    "content_validation": True,

                    "heartbeat_system": True,

                    "extended_timeouts": True

                },

                "network_settings": {

                    "heartbeat_interval": getattr(self.p2p_node, 'heartbeat_interval', 30),

                    "connection_timeout": getattr(self.p2p_node, 'connection_timeout', 120),

                    "reconnect_attempts": getattr(self.p2p_node, 'reconnect_attempts', 3)

                },

                "access_mode": "localhost_only",

                "platform_support": "Windows_Linux_macOS",

                "node_status": "active" if self.p2p_node else "inactive"

            }

            

            self._send_json_response(status)

            

        except Exception as e:

            print(f"[API] Status error: {e}")

            traceback.print_exc()

            self._send_json_response({

                "error": f"Status retrieval error: {str(e)}",

                "version": "2.1"

            }, 500)



    def _handle_get_peers(self):

        """Handle peers list request"""

        try:

            if not self.p2p_node:

                self._send_json_response({"error": "P2P node not available"}, 500)

                return



            peers = []

            if hasattr(self.p2p_node, 'get_peer_list'):

                peer_list = self.p2p_node.get_peer_list()

                for peer_addr in peer_list:

                    peers.append({

                        "host": peer_addr[0],

                        "port": peer_addr[1],

                        "address": f"{peer_addr[0]}:{peer_addr[1]}",

                        "status": "connected"

                    })



            self._send_json_response({

                "connected_peers": peers,

                "count": len(peers),

                "max_peers": getattr(self.p2p_node, 'max_peers', 9)

            })



        except Exception as e:

            print(f"[API] Peers error: {e}")

            self._send_json_response({"error": f"Peers retrieval error: {str(e)}"}, 500)



    def _handle_get_peer_status(self):

        """Handle detailed peer status request"""

        try:

            if not self.p2p_node or not hasattr(self.p2p_node, 'get_peer_status_info'):

                self._send_json_response({"error": "Peer status not available"}, 500)

                return



            peer_status = self.p2p_node.get_peer_status_info()

            

            enhanced_status = {}

            for peer_addr, status in peer_status.items():

                enhanced_status[peer_addr] = {

                    "platform": status.get('platform', 'unknown'),

                    "user_id": status.get('user_id', 'unknown'),

                    "connected_duration": status.get('connected_duration', '0s'),

                    "last_heartbeat": status.get('last_heartbeat', 'never'),

                    "is_alive": status.get('is_alive', False),

                    "connection_quality": "good" if status.get('is_alive', False) else "poor"

                }



            self._send_json_response({

                "peer_status": enhanced_status,

                "total_peers": len(enhanced_status),

                "alive_peers": len([s for s in enhanced_status.values() if s['is_alive']]),

                "dead_peers": len([s for s in enhanced_status.values() if not s['is_alive']])

            })



        except Exception as e:

            print(f"[API] Peer status error: {e}")

            self._send_json_response({"error": f"Peer status error: {str(e)}"}, 500)



    def _handle_content_validation_log(self, limit=50, valid_only=False, invalid_only=False):

        """Handle content validation log request"""

        try:

            if not self.p2p_node or not hasattr(self.p2p_node, 'get_content_validation_log'):

                self._send_json_response({"error": "Content validation log not available"}, 500)

                return



            content_log = self.p2p_node.get_content_validation_log()

            

         

            if valid_only:

                content_log = [c for c in content_log if c['is_valid']]

            elif invalid_only:

                content_log = [c for c in content_log if not c['is_valid']]

            

           

            if limit > 0:

                content_log = content_log[-limit:]



       

            formatted_log = []

            for entry in content_log:

                formatted_entry = entry.copy()

                if isinstance(formatted_entry.get('timestamp'), (int, float)):

                    formatted_entry['formatted_timestamp'] = time.strftime(

                        '%Y-%m-%d %H:%M:%S', 

                        time.localtime(formatted_entry['timestamp'])

                    )

                formatted_log.append(formatted_entry)



            self._send_json_response({

                "validation_log": formatted_log,

                "total_entries": len(content_log),

                "filters_applied": {

                    "limit": limit,

                    "valid_only": valid_only,

                    "invalid_only": invalid_only

                }

            })



        except Exception as e:

            print(f"[API] Content validation log error: {e}")

            self._send_json_response({"error": f"Content validation log error: {str(e)}"}, 500)



    def _handle_network_stats(self):

        """Handle network statistics request"""

        try:

            if not self.p2p_node:

                self._send_json_response({"error": "P2P node not available"}, 500)

                return



            stats = {

                "network_health": "unknown",

                "connected_peers": 0,

                "known_peers": 0,

                "max_peers": getattr(self.p2p_node, 'max_peers', 9),

                "auto_reconnect_active": True,

                "heartbeat_system": True,

                "content_validation": True,

                "settings": {

                    "heartbeat_interval": getattr(self.p2p_node, 'heartbeat_interval', 30),

                    "connection_timeout": getattr(self.p2p_node, 'connection_timeout', 120),

                    "reconnect_attempts": getattr(self.p2p_node, 'reconnect_attempts', 3)

                }

            }



     

            if hasattr(self.p2p_node, 'peers'):

                stats["connected_peers"] = len(self.p2p_node.peers)

            

            if hasattr(self.p2p_node, 'known_peers'):

                stats["known_peers"] = len(self.p2p_node.known_peers)



         


            peer_ratio = stats["connected_peers"] / stats["max_peers"]

            if peer_ratio >= 0.7:

                stats["network_health"] = "excellent"

            elif peer_ratio >= 0.4:

                stats["network_health"] = "good"

            elif peer_ratio >= 0.1:

                stats["network_health"] = "poor"

            else:

                stats["network_health"] = "isolated"



      

            if hasattr(self.p2p_node, 'get_content_validation_log'):

                content_log = self.p2p_node.get_content_validation_log()

                stats["content_stats"] = {

                    "total_messages": len(content_log),

                    "valid_messages": len([c for c in content_log if c['is_valid']]),

                    "invalid_messages": len([c for c in content_log if not c['is_valid']]),

                    "validation_success_rate": 0

                }

                

                if len(content_log) > 0:

                    stats["content_stats"]["validation_success_rate"] = (

                        stats["content_stats"]["valid_messages"] / len(content_log) * 100

                    )



            self._send_json_response(stats)



        except Exception as e:

            print(f"[API] Network stats error: {e}")

            self._send_json_response({"error": f"Network stats error: {str(e)}"}, 500)



    def _handle_known_peers(self):

        """Handle known peers request"""

        try:

            if not self.p2p_node or not hasattr(self.p2p_node, 'known_peers'):

                self._send_json_response({"error": "Known peers not available"}, 500)

                return



            known_peers = []

            connected_peers = set()

            

            if hasattr(self.p2p_node, 'peers'):

                connected_peers = set(self.p2p_node.peers.keys())



            for peer_addr in self.p2p_node.known_peers:

                host, port = peer_addr

                is_connected = peer_addr in connected_peers

                

                known_peers.append({

                    "host": host,

                    "port": port,

                    "address": f"{host}:{port}",

                    "is_connected": is_connected,

                    "status": "connected" if is_connected else "disconnected"

                })



            self._send_json_response({

                "known_peers": known_peers,

                "total_known": len(known_peers),

                "connected": len([p for p in known_peers if p['is_connected']]),

                "disconnected": len([p for p in known_peers if not p['is_connected']])

            })



        except Exception as e:

            print(f"[API] Known peers error: {e}")

            self._send_json_response({"error": f"Known peers error: {str(e)}"}, 500)



    def _handle_connect_peer(self, data):

        """Handle connect peer request"""

        host = data.get("host")

        port = data.get("port", 4000)

        

        if not host:

            self._send_json_response({"error": "Host required"}, 400)

            return



        try:

            if not self.p2p_node or not hasattr(self.p2p_node, 'connect_to_peer'):

                self._send_json_response({"error": "P2P node not available"}, 500)

                return



            success = self.p2p_node.connect_to_peer(host, port)

            

            if success:

                response = {

                    "success": True,

                    "host": host,

                    "port": port,

                    "message": f"Successfully connected to {host}:{port}"

                }

            else:

                response = {

                    "success": False,

                    "host": host,

                    "port": port,

                    "message": f"Failed to connect to {host}:{port}"

                }



            self._send_json_response(response)



        except Exception as e:

            print(f"[API] Connect peer error: {e}")

            self._send_json_response({"error": f"Connect error: {str(e)}"}, 500)



    def _handle_broadcast_content(self, data):

        """CORRECTION: Handle broadcast content request avec la nouvelle méthode"""

        site_name = data.get("site") or data.get("site_name")

        content = data.get("content")

        

        if not site_name or not content:

            self._send_json_response({"error": "Site name and content required"}, 400)

            return



        try:

            if not self.p2p_node:

                self._send_json_response({"error": "P2P node not available"}, 500)

                return




            success = self.p2p_node.broadcast_content_to_network(site_name, content)

            

            if success:

                user_id = "unknown"

                if hasattr(self.p2p_node, 'crypto') and self.p2p_node.crypto:

                    user_id = getattr(self.p2p_node.crypto, 'crypto_id', 'unknown')



                response = {

                    "success": True,

                    "site_name": site_name,

                    "content": content[:100] + "..." if len(content) > 100 else content,

                    "author": user_id,

                    "peers_notified": len(getattr(self.p2p_node, 'peers', {})),

                    "broadcast_method": "network_wide",

                    "signature_created": True,

                    "validation_passed": True,

                    "message": "Content broadcast successfully to all connected peers"

                }

                print(f"[API] ✓ Content broadcast: {site_name} -> {len(getattr(self.p2p_node, 'peers', {}))} peers")

                self._send_json_response(response)

            else:

                response = {

                    "success": False,

                    "site_name": site_name,

                    "error": "Failed to broadcast content - check site exists and signature creation",

                    "troubleshooting": {

                        "check_site_exists": f"Verify site '{site_name}' is registered locally",

                        "check_keys": "Ensure cryptographic keys are available",

                        "check_peers": "Verify peer connections are active"

                    }

                }

                print(f"[API] ✗ Content broadcast failed: {site_name}")

                self._send_json_response(response, 500)



        except Exception as e:

            print(f"[API] Broadcast content error: {e}")

            traceback.print_exc()

            self._send_json_response({

                "error": f"Broadcast error: {str(e)}",

                "site_name": site_name,

                "troubleshooting": "Check server logs for detailed error information"

            }, 500)



    

    def _handle_get_sites(self):

        """Handle site retrieval"""

        try:

            if not self.p2p_node or not hasattr(self.p2p_node, 'database'):

                self._send_json_response({"error": "Database not available"}, 500)

                return



            sites = self.p2p_node.database.get_sites()

            

            if not sites:

                self._send_json_response([])

                return

            

            enhanced_sites = []

            for site in sites:

                enhanced_site = {

                    "site_name": site.get("site_name", "Unknown"),

                    "owner_id": site.get("owner_id", "Unknown"),

                    "created_at": site.get("created_at", "Unknown"),

                    "falcon_public": site.get("falcon_public"),

                    "dilithium_public": site.get("dilithium_public")

                }

                

                try:

                    site_keys = self.p2p_node.database.get_site_keys(site.get("site_name"))

                    if site_keys:

                        enhanced_site["falcon_private"] = site_keys.get("falcon_private")

                        enhanced_site["dilithium_private"] = site_keys.get("dilithium_private")

                except:

                    pass

                

                enhanced_sites.append(enhanced_site)

            

            self._send_json_response(enhanced_sites)

            

        except Exception as e:

            print(f"[API] Site retrieval error: {e}")

            traceback.print_exc()

            self._send_json_response({"error": f"Site retrieval error: {str(e)}"}, 500)



    def _handle_get_userid(self):

        """Handle user ID retrieval"""

        try:

            user_id = "unknown"

            

            if self.p2p_node and hasattr(self.p2p_node, 'crypto') and self.p2p_node.crypto:

                user_id = getattr(self.p2p_node.crypto, 'crypto_id', 'unknown')

            

            user_data = {"user_id": user_id}

            self._send_json_response(user_data)

            

        except Exception as e:

            print(f"[API] User ID retrieval error: {e}")

            self._send_json_response({"error": f"ID retrieval error: {str(e)}"}, 500)



    def _handle_get_site_keys(self, site_name):

        """Handle site keys retrieval"""

        if not site_name:

            self._send_json_response({"error": "Site name required"}, 400)

            return



        try:

            if not self.p2p_node or not hasattr(self.p2p_node, 'database'):

                self._send_json_response({"error": "Database not available"}, 500)

                return



            keys = self.p2p_node.database.get_site_keys(site_name)

            

            if keys:

                public_keys = {

                    "falcon_public": keys.get("falcon_public"),

                    "dilithium_public": keys.get("dilithium_public"),

                    "falcon_private": keys.get("falcon_private"),

                    "dilithium_private": keys.get("dilithium_private")

                }

                self._send_json_response(public_keys)

            else:

                self._send_json_response({"error": "Site not found"}, 404)

                

        except Exception as e:

            print(f"[API] Key retrieval error: {e}")

            traceback.print_exc()

            self._send_json_response({"error": f"Key retrieval error: {str(e)}"}, 500)



    def _handle_get_content(self, site_name, author):

        """Handle content retrieval"""

        try:

            if not self.p2p_node or not hasattr(self.p2p_node, 'database'):

                self._send_json_response({"error": "Database not available"}, 500)

                return



            contents = self.p2p_node.database.get_content(site_name=site_name, author_id=author)

            

            if not contents:

                self._send_json_response([])

                return

            

            clean_contents = []

            for content in contents:

                clean_content = {

                    "site_name": content.get("site_name", "Unknown"),

                    "content": content.get("content", ""),

                    "author_id": content.get("author_id", "Anonymous"),

                    "timestamp": content.get("timestamp"),

                    "created_at": content.get("created_at"),

                    "signature": content.get("signature", "")

                }

                clean_contents.append(clean_content)

                

            self._send_json_response(clean_contents)

            

        except Exception as e:

            print(f"[API] Content retrieval error: {e}")

            traceback.print_exc()

            self._send_json_response({"error": f"Content retrieval error: {str(e)}"}, 500)



    def _handle_create_site(self, data):

        """Handle site creation"""

        site_name = data.get("site") or data.get("site_name")

        if not site_name:

            self._send_json_response({"error": "Site name required"}, 400)

            return



        try:

            if not self.p2p_node:

                self._send_json_response({"error": "P2P node not available"}, 500)

                return



          

            if hasattr(self.p2p_node, 'database'):

                existing_sites = self.p2p_node.database.get_sites()

                if existing_sites:

                    for site in existing_sites:

                        if site.get('site_name') == site_name:

                            self._send_json_response({"error": "Site already exists"}, 409)

                            return

            


            keys_data = {}

            if hasattr(self.p2p_node, 'crypto') and self.p2p_node.crypto:

                try:

                    falcon_private, falcon_public = self.p2p_node.crypto.generate_falcon_keypair()

                    dilithium_private, dilithium_public = self.p2p_node.crypto.generate_dilithium_keypair()

                    

                    keys_data = {

                        "falcon_private": falcon_private.hex(),

                        "falcon_public": falcon_public.hex(),

                        "dilithium_private": dilithium_private.hex(),

                        "dilithium_public": dilithium_public.hex()

                    }

                except Exception as e:

                    print(f"[API] Key generation error: {e}")

            


            user_id = "unknown"

            if hasattr(self.p2p_node, 'crypto') and self.p2p_node.crypto:

                user_id = getattr(self.p2p_node.crypto, 'crypto_id', 'unknown')

            


            success = False

            if hasattr(self.p2p_node, 'database'):

                success = self.p2p_node.database.store_site(

                    site_name=site_name,

                    owner_id=user_id,

                    keys_data=keys_data

                )

            

            if success:

                response = {

                    "success": True,

                    "site_name": site_name,

                    "owner": user_id,

                    "message": "Site created successfully"

                }

                response.update(keys_data)

                self._send_json_response(response)

            else:

                self._send_json_response({"error": "Site creation failed"}, 500)

                

        except Exception as e:

            print(f"[API] Site creation error: {e}")

            traceback.print_exc()

            self._send_json_response({"error": f"Site creation error: {str(e)}"}, 500)



    def _handle_post_content(self, data):

        """CORRECTION: Handle content posting with proper broadcast"""

        site_name = data.get("site") or data.get("site_name")

        content = data.get("content")

        

        if not site_name or not content:

            self._send_json_response({"error": "Site name and content required"}, 400)

            return



        try:

            if not self.p2p_node:

                self._send_json_response({"error": "P2P node not available"}, 500)

                return




            success = self.p2p_node.broadcast_content_to_network(site_name, content)

            

            if success:

                user_id = "unknown"

                if hasattr(self.p2p_node, 'crypto') and self.p2p_node.crypto:

                    user_id = getattr(self.p2p_node.crypto, 'crypto_id', 'unknown')



                response = {

                    "success": True,

                    "site_name": site_name,

                    "content": content,

                    "author": user_id,

                    "broadcast_to_peers": True,

                    "peers_notified": len(getattr(self.p2p_node, 'peers', {})),

                    "message": "Content posted and broadcast to network successfully"

                }

                print(f"[API] ✓ Content posted and broadcast: {site_name}")

                self._send_json_response(response)

            else:

                self._send_json_response({"error": "Content posting and broadcast failed"}, 500)

                

        except Exception as e:

            print(f"[API] Content posting error: {e}")

            traceback.print_exc()

            self._send_json_response({"error": f"Content posting error: {str(e)}"}, 500)



    def _handle_crypto_transaction(self, data):

        """Handle crypto transactions with tax system"""

        try:

            transaction_type = data.get("type", "transfer")

            amount = float(data.get("amount", 0))

            wallet_address = data.get("wallet")

            cryptocurrency = data.get("cryptocurrency", "bitcoin")

            sender_tax_paid = data.get("sender_tax_paid", False)

            receiver_tax_paid = data.get("receiver_tax_paid", False)

            

            if amount <= 0:

                self._send_json_response({"error": "Invalid amount"}, 400)

                return

            

            if not wallet_address:

                self._send_json_response({"error": "Wallet address required"}, 400)

                return

            

           

            tax_rate = 0.02

            tax_amount = amount * tax_rate

            

            


            if not sender_tax_paid or not receiver_tax_paid:

                missing_confirmations = []

                if not sender_tax_paid:

                    missing_confirmations.append("sender")

                if not receiver_tax_paid:

                    missing_confirmations.append("receiver")

                

                response = {

                    "success": False,

                    "transaction_blocked": True,

                    "reason": "Dual tax confirmation required",

                    "missing_confirmations": missing_confirmations,

                    "amount": amount,

                    "tax_amount": tax_amount,

                    "tax_rate_percent": tax_rate * 100,

                    "total_required": amount + tax_amount,

                    "cryptocurrency": cryptocurrency,

                    "message": f"Transaction blocked: {tax_rate * 100}% tax confirmation required (${tax_amount:.2f})"

                }

                self._send_json_response(response, 402)

                return

            


            net_amount = amount - tax_amount

            

           

            transaction_id = f"tx_{'unknown'}_{int(datetime.datetime.now().timestamp())}"

            if self.p2p_node and hasattr(self.p2p_node, 'crypto') and self.p2p_node.crypto:

                user_id = getattr(self.p2p_node.crypto, 'crypto_id', 'unknown')

                transaction_id = f"tx_{user_id[:8]}_{int(datetime.datetime.now().timestamp())}"

            

            response = {

                "success": True,

                "transaction_id": transaction_id,

                "type": transaction_type,

                "gross_amount": amount,

                "tax_amount": tax_amount,

                "net_amount": net_amount,

                "tax_rate_percent": tax_rate * 100,

                "cryptocurrency": cryptocurrency,

                "wallet": wallet_address,

                "sender_confirmed": sender_tax_paid,

                "receiver_confirmed": receiver_tax_paid,

                "processed_at": datetime.datetime.now().isoformat(),

                "message": "Transaction processed successfully"

            }

            

            self._send_json_response(response)

            

        except Exception as e:

            print(f"[API] Crypto transaction error: {e}")

            traceback.print_exc()

            self._send_json_response({"error": f"Transaction error: {str(e)}"}, 500)




def start_api_server(node, host="127.0.0.1", port=5001, localhost_only=True):

    """Start enhanced API server - Secured localhost ONLY on port 5001"""

    

    APIHandler.set_p2p_node(node)

    

    if localhost_only:

        host = "127.0.0.1"

        print(f"[API] SECURITY: Localhost only mode - binding to 127.0.0.1 ONLY")

    

    try:

        server = HTTPServer((host, port), APIHandler)

        print(f"[API] Enhanced server started successfully on {host}:{port}")

        print(f"[API] Access URL: http://127.0.0.1:{port}")

        print(f"[API] CORRECTION: Content transmission flow fixed")

        print(f"[API] New endpoints: /api/content_validation_log, /api/peer_status, /api/network_stats")

        print(f"[API] SECURITY: Remote access BLOCKED - localhost only")

        print(f"[API] Multi-platform: Compatible Windows/Linux/macOS")

        return server

        

    except PermissionError as e:

        print(f"[API] Permission error on port {port}: {e}")

        alt_port = port + 1000

        try:

            server = HTTPServer(("127.0.0.1", alt_port), APIHandler)

            print(f"[API] *** FALLBACK: Server started on port {alt_port} ***")

            print(f"[API] *** USE THIS URL: http://127.0.0.1:{alt_port} ***")

            return server

        except Exception as alt_e:

            print(f"[API] Fallback port {alt_port} failed: {alt_e}")

            raise Exception(f"Unable to bind to ports {port} or {alt_port}")

            

    except Exception as e:

        print(f"[API] Server startup error: {e}")

        raise

 