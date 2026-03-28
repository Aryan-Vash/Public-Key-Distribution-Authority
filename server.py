# server.py
import time
from RSA.rsa_engine import RSAEngine

class PKDA:
    def __init__(self):
        print("[PKDA] Initializing and generating 128-bit master RSA keys...")
        self.public_key, self.private_key = RSAEngine.generate_keys(bits=128)
        self.directory = {}  # Format: { "client_id": "e,n" }
        print("[PKDA] Online and ready.")

    def register_client(self, client_id, public_key):
        """Stores a client's public key. Formats the tuple (e, n) as a string 'e,n'."""
        e, n = public_key
        self.directory[client_id] = f"{e},{n}"
        print(f"[PKDA] Registered Public Key for '{client_id}'")

    def get_key(self, target_id, requester_id, timestamp):
        """
        Step 2 & Step 5 of the handshake.
        Formats: Target_Key || Initiator_ID || Responder_ID || Time || Duration
        """
        if target_id not in self.directory:
            raise ValueError(f"[PKDA ERROR] Client '{target_id}' not found in directory.")

        target_pub_key_str = self.directory[target_id]

        duration = 86400  # Key TTL
        msg_ttl = 4800   # Message TTL
        
        # New Format: Key || Requester || Target || Time || Msg_TTL || Key_TTL
        payload = f"{target_pub_key_str}||{requester_id}||{target_id}||{timestamp}||{msg_ttl}||{duration}"

        # Encrypt with PKDA private key
        ciphertext = RSAEngine.encrypt(payload, self.private_key)
        return ciphertext