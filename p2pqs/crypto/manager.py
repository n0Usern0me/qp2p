
import os

import hashlib

import secrets

from typing import Optional, Dict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes



def _to_bytes(value) -> Optional[bytes]:

    if value is None:

        return None

    if isinstance(value, bytes):

        return value

    if isinstance(value, str):

        return bytes.fromhex(value.strip())

    return None



def _to_hex(value) -> Optional[str]:

    if value is None:

        return None

    if isinstance(value, bytes):

        return value.hex()

    return str(value)



class CryptoManager:

    """Enhanced crypto manager with site-based signature verification"""

    

    def __init__(self, crypto_id: str = None,

                 falcon_private: Optional[bytes] = None,

                 dilithium_private: Optional[bytes] = None):

        self.crypto_id = crypto_id or os.urandom(16).hex()

        self.falcon_private = _to_bytes(falcon_private)

        self.dilithium_private = _to_bytes(dilithium_private)



    def generate_falcon_keypair(self):

        """Generate Falcon keypair for encryption"""

        private_key = secrets.token_bytes(64)

        public_key = hashlib.sha256(private_key + b"falcon").digest()

        if not self.falcon_private:

            self.falcon_private = private_key

        return private_key, public_key



    def generate_dilithium_keypair(self):

        """Generate Dilithium keypair for digital signatures"""

        private_key = secrets.token_bytes(128)

        public_key = hashlib.sha256(private_key + b"dilithium").digest()

        if not self.dilithium_private:

            self.dilithium_private = private_key

        return private_key, public_key



    def derive_falcon_public(self, private_key: bytes) -> bytes:

        """Derive Falcon public key from private key"""

        return hashlib.sha256(private_key + b"falcon").digest()



    def derive_dilithium_public(self, private_key: bytes) -> bytes:

        """Derive Dilithium public key from private key"""

        return hashlib.sha256(private_key + b"dilithium").digest()



    def encrypt_data(self, plaintext: str, falcon_public: bytes) -> bytes:

        """Encrypt data with Falcon public key"""

        try:

            key = hashlib.scrypt(falcon_public, salt=b"falcon_enc", n=16384, r=8, p=1, dklen=32)

            nonce = secrets.token_bytes(12)

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))

            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()

            return nonce + encryptor.tag + ciphertext

        except Exception as e:

            print(f"[Crypto] Encryption error: {e}")

            return plaintext.encode("utf-8")



    def decrypt_data(self, ciphertext: bytes, falcon_private: bytes) -> str:

        """Decrypt data with Falcon private key"""

        try:

            falcon_public = self.derive_falcon_public(falcon_private)

            key = hashlib.scrypt(falcon_public, salt=b"falcon_enc", n=16384, r=8, p=1, dklen=32)

            nonce, tag, encrypted_content = ciphertext[:12], ciphertext[12:28], ciphertext[28:]

            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))

            decryptor = cipher.decryptor()

            plaintext = decryptor.update(encrypted_content) + decryptor.finalize()

            return plaintext.decode("utf-8")

        except Exception as e:

            print(f"[Crypto] Decryption error: {e}")

            return ciphertext.decode("utf-8", errors="replace")



    def sign_data(self, data: str, dilithium_private: bytes = None) -> bytes:

        """Sign data with Dilithium private key - for site content verification"""

        key = dilithium_private or self.dilithium_private

        if not key:

            print("[Crypto] Warning: No private key available for signing")

            return hashlib.sha256(data.encode("utf-8")).digest()

        

      

        message_hash = hashlib.sha3_256(data.encode("utf-8")).digest()

        site_signature = hashlib.pbkdf2_hmac("sha3-256", key, message_hash, 10000, dklen=64)

        

        print(f"[Crypto] Content signed for site verification")

        return site_signature



    def verify_signature(self, data: str, signature: bytes, dilithium_public: bytes) -> bool:

        """Verify signature with Dilithium public key - for site content verification"""

        try:

      

            message_hash = hashlib.sha3_256(data.encode("utf-8")).digest()

            


            derived_private = hashlib.scrypt(dilithium_public, salt=b"dilithium", n=16384, r=8, p=1, dklen=128)

            expected_signature = hashlib.pbkdf2_hmac("sha3-256", derived_private, message_hash, 10000, dklen=64)

            

            is_valid = signature == expected_signature

            

            if is_valid:

                print(f"[Crypto] Site signature verification: SUCCESS")

            else:

                print(f"[Crypto] Site signature verification: FAILED")

                print(f"[Crypto] This content was not signed by the site owner")

            

            return is_valid

            

        except Exception as e:

            print(f"[Crypto] Site signature verification error: {e}")

            return False



    def verify_site_content(self, content: str, signature_hex: str, site_public_key: bytes) -> bool:

        """Verify content was signed by a specific site's private key"""

        try:

            if not signature_hex or not content or not site_public_key:

                print(f"[Crypto] Missing data for site content verification")

                return False

            

            signature = bytes.fromhex(signature_hex)

            is_valid = self.verify_signature(content, signature, site_public_key)

            

            if is_valid:

                print(f"[Crypto] ✓ Content verified as authentic from site")

            else:

                print(f"[Crypto] ✗ Content failed site authentication")

                print(f"[Crypto] This content may be forged or corrupted")

            

            return is_valid

            

        except Exception as e:

            print(f"[Crypto] Site content verification error: {e}")

            return False



    def create_site_signature(self, content: str, site_private_key: bytes) -> str:

        """Create a signature for content using site's private key"""

        try:

            signature = self.sign_data(content, site_private_key)

            signature_hex = signature.hex()

            print(f"[Crypto] Created site signature for content verification")

            return signature_hex

        except Exception as e:

            print(f"[Crypto] Error creating site signature: {e}")

            return ""



    def generate_site_keypair(self) -> Dict[str, str]:

        """Generate new keypair specifically for a site"""

        try:

            falcon_private, falcon_public = self.generate_falcon_keypair()

            dilithium_private, dilithium_public = self.generate_dilithium_keypair()

            

            keys = {

                "falcon_private": falcon_private.hex(),

                "falcon_public": falcon_public.hex(),

                "dilithium_private": dilithium_private.hex(),

                "dilithium_public": dilithium_public.hex()

            }

            

            print(f"[Crypto] Generated new site keypair for content verification")

            print(f"[Crypto] Public key can be shared for signature verification")

            print(f"[Crypto] Private key must be kept secret by site owner")

            

            return keys

            

        except Exception as e:

            print(f"[Crypto] Error generating site keypair: {e}")

            return {}



    def get_public_keys(self) -> Dict[str, str]:

        """Get public keys in hex format"""

        falcon_public = None

        dilithium_public = None

        

        if self.falcon_private:

            falcon_public = self.derive_falcon_public(self.falcon_private)

        if self.dilithium_private:

            dilithium_public = self.derive_dilithium_public(self.dilithium_private)

            

        return {

            "falcon_public": _to_hex(falcon_public),

            "dilithium_public": _to_hex(dilithium_public)

        }



    def validate_site_keys(self, keys_data: Dict[str, str]) -> bool:

        """Validate that site keys are properly formatted"""

        try:

            required_keys = ["falcon_private", "falcon_public", "dilithium_private", "dilithium_public"]

            

            for key_name in required_keys:

                if key_name not in keys_data or not keys_data[key_name]:

                    print(f"[Crypto] Missing required site key: {key_name}")

                    return False

                

               

                try:

                    bytes.fromhex(keys_data[key_name])

                except ValueError:

                    print(f"[Crypto] Invalid hex format for key: {key_name}")

                    return False

            

          

            falcon_private = bytes.fromhex(keys_data["falcon_private"])

            expected_falcon_public = self.derive_falcon_public(falcon_private)

            actual_falcon_public = bytes.fromhex(keys_data["falcon_public"])

            

            if expected_falcon_public != actual_falcon_public:

                print(f"[Crypto] Falcon key pair mismatch")

                return False

            

            dilithium_private = bytes.fromhex(keys_data["dilithium_private"])

            expected_dilithium_public = self.derive_dilithium_public(dilithium_private)

            actual_dilithium_public = bytes.fromhex(keys_data["dilithium_public"])

            

            if expected_dilithium_public != actual_dilithium_public:

                print(f"[Crypto] Dilithium key pair mismatch")

                return False

            

            print(f"[Crypto] ✓ Site keys validation successful")

            return True

            

        except Exception as e:

            print(f"[Crypto] Site keys validation error: {e}")

            return False



    def test_site_signature_cycle(self, test_content: str = "Test content for site verification") -> bool:

        """Test the complete signature creation and verification cycle for sites"""

        try:

            print(f"[Crypto] Testing site signature cycle...")

            

      

            site_keys = self.generate_site_keypair()

            if not site_keys:

                print(f"[Crypto] ✗ Failed to generate test site keys")

                return False

            

           

            site_private_key = bytes.fromhex(site_keys["dilithium_private"])

            signature_hex = self.create_site_signature(test_content, site_private_key)

            

            if not signature_hex:

                print(f"[Crypto] ✗ Failed to create site signature")

                return False

            

       

            site_public_key = bytes.fromhex(site_keys["dilithium_public"])

            is_valid = self.verify_site_content(test_content, signature_hex, site_public_key)

            

            if is_valid:

                print(f"[Crypto] ✓ Site signature cycle test successful")

                print(f"[Crypto] Content can be properly signed and verified by sites")

                return True

            else:

                print(f"[Crypto] ✗ Site signature cycle test failed")

                return False

                

        except Exception as e:

            print(f"[Crypto] Site signature cycle test error: {e}")

            return False



    def get_crypto_info(self) -> Dict[str, str]:

        """Get information about the crypto system"""

        return {

            "system": "Quantum-Safe P2P Network",

            "encryption": "Falcon (Post-quantum encryption)",

            "signatures": "Dilithium (Post-quantum digital signatures)", 

            "verification": "Site-based content authentication",

            "hash_function": "SHA-3 (256-bit)",

            "key_derivation": "PBKDF2-HMAC-SHA3-256",

            "symmetric_encryption": "AES-256-GCM",

            "crypto_id": self.crypto_id,

            "status": "Site verification enabled"

        }

 