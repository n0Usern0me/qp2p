import os

import json

import secrets

from typing import Dict, Any



DEFAULT_CONFIG = {

    "user_id": None,

    "node": {

        "enable_http": True,

        "api_host": "127.0.0.1",  

        "api_port": 5001,  

        "p2p_port": 4000,

        "localhost_only": True,

        "cross_platform": True  

    },

    "security": {

        "keys": {

            "falcon": None,

            "dilithium": None

        },

        "strict_localhost": True,

        "log_access_attempts": True,

        "dual_tax_confirmation": True  

    },

    "language": {

        "interface": "english",

        "remove_other_languages": True

    }

}



class ConfigManager:

    def __init__(self, path: str = "config.json"):

        self.path = path

        self.config: Dict[str, Any] = {}

        self.load()



    def load(self):

        """Load configuration with security defaults"""

        if os.path.exists(self.path):

            try:

                with open(self.path, "r", encoding="utf-8") as f:

                    loaded_config = json.load(f)

                    

               

                self.config = DEFAULT_CONFIG.copy()

                self._merge_config(self.config, loaded_config)

                

            except Exception as e:

                print(f"[Config] Load error: {e}")

                self.config = DEFAULT_CONFIG.copy()

        else:

            self.config = DEFAULT_CONFIG.copy()

            

      

        if not self.config.get("user_id"):

            self.config["user_id"] = secrets.token_hex(16)

            

        

        self._enforce_security()

        self.save()



    def _merge_config(self, default: dict, loaded: dict):

        """Merge loaded config with defaults recursively"""

        for key, value in loaded.items():

            if key in default:

                if isinstance(value, dict) and isinstance(default[key], dict):

                    self._merge_config(default[key], value)

                else:

                    default[key] = value



    def _enforce_security(self):

        """Enforce security settings - ENGLISH ONLY"""

    

        if self.config.get("node"):

            self.config["node"]["api_host"] = "127.0.0.1"

            self.config["node"]["api_port"] = 5001   

            self.config["node"]["localhost_only"] = True

            self.config["node"]["cross_platform"] = True

            

    

        if not self.config.get("security"):

            self.config["security"] = DEFAULT_CONFIG["security"].copy()

        else:

            self.config["security"]["strict_localhost"] = True

            self.config["security"]["log_access_attempts"] = True

            self.config["security"]["dual_tax_confirmation"] = True



       

        if not self.config.get("language"):

            self.config["language"] = DEFAULT_CONFIG["language"].copy()

        else:

            self.config["language"]["interface"] = "english"

            self.config["language"]["remove_other_languages"] = True





    def _handle_broadcast_content(self, data):

        """Handle broadcast content request with proper method"""

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



    def _handle_post_content(self, data):

        """Handle content posting with proper broadcast"""

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

 

 