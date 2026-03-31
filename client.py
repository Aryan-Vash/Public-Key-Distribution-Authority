# client.py
import time
import random
import os
from datetime import datetime
import hashlib
from RSA.rsa_engine import RSAEngine

class Client:
    def __init__(self, client_id, pkda_server):
        self.id = client_id
        self.pkda = pkda_server
        self.known_hosts = {}  # Local cache for verified public keys
        
        # Initialize the client and generate a 128-bit RSA key pair
        print(f"[{self.id}] Generating 128-bit RSA keys...")
        self.public_key, self.private_key = RSAEngine.generate_keys(bits=128)

        # Register the public key with the central authority
        self.pkda.register_client(self.id, self.public_key)

    def _log_trace(self, target_id, direction, step_name, data, ciphertext=None):
        """
        Logs network interactions to pair-specific and global trace files 
        within a dynamically created 'traces' directory.
        """
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        except NameError:
            base_dir = os.path.abspath(os.getcwd())
            
        traces_folder = os.path.join(base_dir, "traces")
        if not os.path.exists(traces_folder):
            os.makedirs(traces_folder)
        
        # Ensure consistent file naming for client pairs
        pair = sorted([str(self.id), str(target_id)])
        pair_filepath = os.path.join(traces_folder, f"{pair[0]}_{pair[1]}_trace.txt")
        global_filepath = os.path.join(traces_folder, "Global_Handshake_Log.txt")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Build the log entry with both plaintext and ciphertext
        log_entry = f"[{timestamp}] {direction} | {step_name}\nPlaintext Payload: {data}\n"
        if ciphertext:
            log_entry += f"Ciphertext: {ciphertext}\n"
        log_entry += ("-" * 60) + "\n"
        
        with open(pair_filepath, "a", encoding="utf-8") as f:
            f.write(log_entry)
        with open(global_filepath, "a", encoding="utf-8") as f:
            f.write(log_entry)
            
        print(f"      -> [TRACE SAVED IN FOLDER: {traces_folder}]")


    def _get_cached_key(self, target_id):
        """
        Retrieves a public key from the local cache. Evicts the key 
        if the current time exceeds its Time-To-Live (TTL).
        """
        if target_id not in self.known_hosts:
            return None
        
        cached_data = self.known_hosts[target_id]
        
        if int(time.time()) > cached_data['expires_at']:
            print(f"[{self.id}] Cache Expired: Public key for {target_id} has exceeded its TTL.")
            del self.known_hosts[target_id]
            return None
            
        return cached_data['key']

    def _request_key_from_pkda(self, target_id):
        print(f"[{self.id} -> PKDA] Requesting public key for {target_id}...")
        current_time = int(time.time())
        
        req_payload = f"{self.id}||{target_id}||{current_time}"
        self._log_trace("PKDA", f"{self.id} -> PKDA", f"Requesting {target_id}'s Key", req_payload)
        
        ciphertext = self.pkda.get_key(target_id, self.id, current_time)
        plaintext = RSAEngine.decrypt(ciphertext, self.pkda.public_key)
        
        # ADDED CIPHERTEXT HERE
        self._log_trace("PKDA", f"PKDA -> {self.id}", f"Received {target_id}'s Key", plaintext, ciphertext)
        
        parts = plaintext.split("||")
        target_key_str = parts[0]
        req_id = parts[1]
        tgt_id = parts[2]
        timestamp = int(parts[3])
        msg_ttl = int(parts[4])
        key_ttl = int(parts[5])
        
        if current_time - timestamp > msg_ttl:
             raise Exception(f"[{self.id}] SECURITY ALERT: PKDA response delayed or replayed!")
             
        e, n = map(int, target_key_str.split(','))
        self.known_hosts[target_id] = {'key': (e, n), 'expires_at': current_time + key_ttl}
        print(f"[{self.id}] Decrypted PKDA response. Acquired trusted key for {target_id}.")
        return (e, n)

    # ==========================================
    # --- CRYPTOGRAPHIC HANDSHAKE PROTOCOL ---
    # ==========================================

    def initiate_handshake(self, target_client):
        print(f"\n--- HANDSHAKE START: {self.id} -> {target_client.id} ---")

        target_pub_key = self._get_cached_key(target_client.id)
        if not target_pub_key:
            target_pub_key = self._request_key_from_pkda(target_client.id)
        
        self.n1 = random.randint(100000, 999999)
        current_time = int(time.time())
        
        payload = f"{self.id}||{target_client.id}||{self.n1}||{current_time}||300"
        print(f"[{self.id} -> {target_client.id}] Sending IDs and Nonce 1 ({self.n1})...")
        
        # MOVED ENCRYPTION ABOVE LOGGING
        ciphertext = RSAEngine.encrypt(payload, target_pub_key)
        self._log_trace(target_client.id, f"{self.id} -> {target_client.id}", "Handshake Step 3 (Sending N1)", payload, ciphertext)
        
        target_client.handle_handshake_request(self, ciphertext)

    def handle_handshake_request(self, sender_client, ciphertext):
        plaintext = RSAEngine.decrypt(ciphertext, self.private_key)
        # LOGGING INCOMING CIPHERTEXT
        self._log_trace(sender_client.id, f"{sender_client.id} -> {self.id}", "Handshake Step 3 (Received N1)", plaintext, ciphertext)
        
        sender_id, target_id_str, n1_str, timestamp, ttl = plaintext.split("||")
        
        if int(time.time()) - int(timestamp) > int(ttl):
            return
            
        print(f"[{self.id}] Received Handshake Request from {sender_id}. Extracted N1: {n1_str}")
        
        sender_pub_key = self._get_cached_key(sender_id)
        if not sender_pub_key:
            sender_pub_key = self._request_key_from_pkda(sender_id)
        
        self.n2 = random.randint(100000, 999999)
        current_time = int(time.time())

        payload = f"{self.id}||{sender_id}||{n1_str}||{self.n2}||{current_time}||300"
        print(f"[{self.id} -> {sender_id}] Returning N1 ({n1_str}) and sending N2 ({self.n2})...")
        
        # MOVED ENCRYPTION ABOVE LOGGING
        reply_ciphertext = RSAEngine.encrypt(payload, sender_pub_key)
        self._log_trace(sender_id, f"{self.id} -> {sender_id}", "Handshake Step 6 (Sending N1+N2)", payload, reply_ciphertext)
        
        sender_client.finish_handshake(self, reply_ciphertext)

    def finish_handshake(self, target_client, ciphertext):
        plaintext = RSAEngine.decrypt(ciphertext, self.private_key)
        # LOGGING INCOMING CIPHERTEXT
        self._log_trace(target_client.id, f"{target_client.id} -> {self.id}", "Handshake Step 6 (Received N1+N2)", plaintext, ciphertext)
        
        responder_id, initiator_id, returned_n1, n2_str, timestamp, ttl = plaintext.split("||")
        
        if int(time.time()) - int(timestamp) > int(ttl):
            print(f"[{self.id}] Handshake failed: Step 6 packet exceeded TTL.")
            return

        if returned_n1 != str(self.n1):
            print(f"[{self.id}] Handshake failed: Nonce 1 verification failed.")
            return
            
        print(f"[{self.id}] Verified N1. Identity of {target_client.id} confirmed.")
        
        target_pub_key = self._get_cached_key(target_client.id)
        if not target_pub_key:
            target_pub_key = self._request_key_from_pkda(target_client.id)
            
        current_time = int(time.time())
        
        payload = f"{self.id}||{target_client.id}||{n2_str}||{current_time}||300"
        print(f"[{self.id} -> {target_client.id}] Sending N2 ({n2_str}) back to finalize...")
        
        # MOVED ENCRYPTION ABOVE LOGGING
        final_ciphertext = RSAEngine.encrypt(payload, target_pub_key)
        self._log_trace(target_client.id, f"{self.id} -> {target_client.id}", "Handshake Step 7 (Sending N2)", payload, final_ciphertext)
        
        target_client.verify_final_handshake(self.id, final_ciphertext)

    def verify_final_handshake(self, sender_id, ciphertext):
        plaintext = RSAEngine.decrypt(ciphertext, self.private_key)
        # LOGGING INCOMING CIPHERTEXT
        self._log_trace(sender_id, f"{sender_id} -> {self.id}", "Handshake Step 7 (Received N2)", plaintext, ciphertext)
        
        initiator_id, responder_id, returned_n2, timestamp, ttl = plaintext.split("||")
        
        if int(time.time()) - int(timestamp) > int(ttl):
            print(f"[{self.id}] Handshake failed: Step 7 packet exceeded TTL.")
            return

        if returned_n2 != str(self.n2):
            print(f"[{self.id}] Handshake failed: Nonce 2 verification failed.")
            return
            
        print(f"[{self.id}] Verified N2. Identity of {sender_id} confirmed.")
        print(f"--- HANDSHAKE COMPLETE: {sender_id} <-> {self.id} ---")


    # ==========================================
    # --- SECURE MESSAGING IMPLEMENTATION ---
    # ==========================================

    def send_secure_message(self, target_client, message):
        target_pub_key = self._get_cached_key(target_client.id)
        if not target_pub_key:
            print(f"[{self.id}] Error: Valid public key for {target_client.id} not found. Execute handshake sequence.")
            return
            
        print(f"[{self.id} -> {target_client.id}] Sending message: '{message}'")
        current_time = int(time.time())
        
        base_payload = f"{self.id}||{target_client.id}||{message}||{current_time}||3600"
        payload_hash = hashlib.sha256(base_payload.encode('utf-8')).hexdigest()
        final_payload = f"{base_payload}||{payload_hash}"
        
        # MOVED ENCRYPTION ABOVE LOGGING
        ciphertext = RSAEngine.encrypt(final_payload, target_pub_key)
        self._log_trace(target_client.id, f"{self.id} -> {target_client.id}", "Secure Message Sent", final_payload, ciphertext)
        
        target_client.receive_secure_message(self, ciphertext)

    def receive_secure_message(self, sender_client, ciphertext):
        plaintext = RSAEngine.decrypt(ciphertext, self.private_key)
        # LOGGING INCOMING CIPHERTEXT
        self._log_trace(sender_client.id, f"{sender_client.id} -> {self.id}", "Secure Message Received", plaintext, ciphertext)
        
        parts = plaintext.split("||")
        received_hash = parts[-1]
        base_payload = "||".join(parts[:-1])
        
        calculated_hash = hashlib.sha256(base_payload.encode('utf-8')).hexdigest()
        if received_hash != calculated_hash:
            print(f"[{self.id}] CRITICAL ERROR: Integrity check failed! Message was tampered with.")
            return
            
        sender_id, target_id, message, timestamp, ttl = parts[0], parts[1], parts[2], parts[3], parts[4]
        
        if int(time.time()) - int(timestamp) > int(ttl):
            print(f"[{self.id}] Message dropped: Exceeded TTL.")
            return
            
        print(f"[{self.id}] Integrity Verified. Decrypted message from {sender_client.id}: '{message}'")

        if message.startswith("Hi"):
            msg_id = message[2:] 
            reply_text = f"Got-it{msg_id}"
            
            print(f"[{self.id}] Automated response triggered. Preparing transmission...")
            time.sleep(1) 
            
            self.send_secure_message(sender_client, reply_text)