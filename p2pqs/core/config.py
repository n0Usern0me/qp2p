

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

                "dual_tax_confirmation": True,

               "bypass_site_verification": "all"

            },

            "language": {

                "interface": "english",

                

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

                    

                # Merge with defaults to ensure security

                self.config = DEFAULT_CONFIG.copy()

                self._merge_config(self.config, loaded_config)

                

            except Exception as e:

                print(f"[Config] Load error: {e}")

                self.config = DEFAULT_CONFIG.copy()

        else:

            self.config = DEFAULT_CONFIG.copy()

            

        # Generate user_id if necessary

        if not self.config.get("user_id"):

            self.config["user_id"] = secrets.token_hex(16)

            

        # FORCE security settings

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

        """Enforce security settings - NO FRENCH"""

        # Force localhost-only for security

        if self.config.get("node"):

            self.config["node"]["api_host"] = "127.0.0.1"

            self.config["node"]["api_port"] = 5001  # Fixed port

            self.config["node"]["localhost_only"] = True

            self.config["node"]["cross_platform"] = True

            

        # Force security settings

        if not self.config.get("security"):

            self.config["security"] = DEFAULT_CONFIG["security"].copy()

        else:

            self.config["security"]["strict_localhost"] = True

            self.config["security"]["log_access_attempts"] = True

            self.config["security"]["dual_tax_confirmation"] = True



        # Force English-only interface

        if not self.config.get("language"):

            self.config["language"] = DEFAULT_CONFIG["language"].copy()

        else:

            self.config["language"]["interface"] = "english"

            self.config["language"]["remove_french"] = True



    def save(self):

        """Save configuration"""

        try:

            # Create backup if file exists

            if os.path.exists(self.path):

                backup_path = f"{self.path}.backup"

                try:

                    with open(self.path, "r") as f:

                        backup_data = f.read()

                    with open(backup_path, "w") as f:

                        f.write(backup_data)

                except:

                    pass  # Backup failed, continue

            

            with open(self.path, "w", encoding="utf-8") as f:

                json.dump(self.config, f, ensure_ascii=False, indent=2)

                

        except Exception as e:

            print(f"[Config] Save error: {e}")



    def update_security_keys(self, crypto):

        """Update security keys from crypto manager"""

        falcon_hex = None

        if getattr(crypto, "falcon_private", None):

            falcon_hex = crypto.falcon_private.hex() if isinstance(crypto.falcon_private, bytes) else crypto.falcon_private

            

        dilithium_hex = None

        if getattr(crypto, "dilithium_private", None):

            dilithium_hex = crypto.dilithium_private.hex() if isinstance(crypto.dilithium_private, bytes) else crypto.dilithium_private



        # Ensure security section exists

        if "security" not in self.config:

            self.config["security"] = DEFAULT_CONFIG["security"].copy()

            

        if "keys" not in self.config["security"]:

            self.config["security"]["keys"] = {}

            

        self.config["security"]["keys"]["falcon"] = falcon_hex

        self.config["security"]["keys"]["dilithium"] = dilithium_hex

        self.save()



    def get_api_settings(self):

        """Get API settings with security enforcement"""

        node_config = self.config.get("node", {})

        return {

            "host": "127.0.0.1",  # ALWAYS localhost

            "port": 5001,  # ALWAYS port 5001

            "localhost_only": True,  # ALWAYS enforce

            "enable_http": node_config.get("enable_http", True),

            "cross_platform": True

        }



    def get_p2p_settings(self):

        """Get P2P settings"""

        node_config = self.config.get("node", {})

        return {

            "port": node_config.get("p2p_port", 4000),

            "max_peers": node_config.get("max_peers", 9)

        }



    def is_localhost_enforced(self):

        """Check if localhost enforcement is active"""

        return self.config.get("security", {}).get("strict_localhost", True)



    def is_dual_tax_required(self):

        """Check if dual tax confirmation is required"""

        return self.config.get("security", {}).get("dual_tax_confirmation", True)



    def get_language_settings(self):

        """Get language settings - English only"""

        return {

            "interface": "english",

            "remove_french": True,

            "supported_languages": ["english"]

        }



    def validate_config(self):

        """Validate configuration security"""

        issues = []

        

        # Check API security

        node_config = self.config.get("node", {})

        if node_config.get("api_host") != "127.0.0.1":

            issues.append("API host should be 127.0.0.1 for security")

            

        if node_config.get("api_port") != 5001:

            issues.append("API port should be 5001")

            

        if not node_config.get("localhost_only", True):

            issues.append("localhost_only should be enabled")

            

        # Check security section

        security = self.config.get("security", {})

        if not security.get("strict_localhost", True):

            issues.append("strict_localhost should be enabled")



        # Check language settings

        language = self.config.get("language", {})

        if language.get("interface") != "english":

            issues.append("Interface should be set to English")

            

        return issues



    def fix_security_issues(self):

        """Fix identified security issues"""

        print("[Config] Fixing security configuration...")

        self._enforce_security()

        self.save()

        print("[Config] Security configuration updated - English only, localhost restricted")



    def reset_to_secure_defaults(self):

        """Reset configuration to secure defaults"""

        print("[Config] Resetting to secure defaults...")

        

        # Preserve user_id and keys if they exist

        old_user_id = self.config.get("user_id")

        old_keys = self.config.get("security", {}).get("keys", {})

        

        # Reset to defaults

        self.config = DEFAULT_CONFIG.copy()

        

        # Restore preserved data

        if old_user_id:

            self.config["user_id"] = old_user_id

        if old_keys:

            self.config["security"]["keys"] = old_keys

            

        self.save()

        print("[Config] Reset completed - English interface, security enforced, port 5001 fixed")



    def get_platform_info(self):

        """Get platform compatibility information"""

        import platform

        system = platform.system().lower()

        

        return {

            "current_platform": system,

            "supported_platforms": ["windows", "linux", "darwin"],

            "cross_platform_mode": self.config.get("node", {}).get("cross_platform", True),

            "optimized_for": "windows_linux" if system in ["windows", "linux"] else "cross_platform"

        }



    def __str__(self):

        """String representation for debugging"""

        safe_config = self.config.copy()

        # Hide sensitive keys

        if "security" in safe_config and "keys" in safe_config["security"]:

            for key_name in ["falcon", "dilithium"]:

                if safe_config["security"]["keys"].get(key_name):

                    safe_config["security"]["keys"][key_name] = "[HIDDEN]"

        

        return f"ConfigManager({json.dumps(safe_config, indent=2)})"

 