import socket
import json
import threading
from electrum.util import ThreadJob

class SilentPaymentScanner(ThreadJob):
    def __init__(self, wallet, db):
        self.wallet = wallet
        self.db = db
        self.server_url = "electrs.cakewallet.com"
        self.server_port = 50001
        self.running = True

    def fetch_tweaks_from_server(self, scan_pubkey: bytes):
        """
        Query the index server for tweaks associated with our scan key.
        This follows the Cake Wallet Silent Payment indexer protocol.
        """
        try:
            with socket.create_connection((self.server_url, self.server_port), timeout=10) as sock:
                # Construct RPC request
                request = {
                    "method": "sp.get_tweaks",
                    "params": [scan_pubkey.hex()],
                    "id": 1,
                    "jsonrpc": "2.0"
                }
                sock.sendall(json.dumps(request).encode() + b'\n')
                response = sock.recv(4096)
                return json.loads(response).get('result', [])
        except Exception as e:
            print(f"Scanner connection error: {e}")
            return []

    def run(self):
        """Background execution loop."""
        scan_pubkey = self.wallet.get_silent_payment_scan_pubkey()
        while self.running:
            tweaks = self.fetch_tweaks_from_server(scan_pubkey)
            for item in tweaks:
                # item: {'txid': ..., 'vout': ..., 'tweak': ...}
                self.db.add_mapping(
                    bytes.fromhex(item['tweak']), 
                    b'', # Logic to map to internal pubkey
                    item['txid'], 
                    item['vout']
                )
            # Sleep to avoid excessive network usage
            threading.Event().wait(300)