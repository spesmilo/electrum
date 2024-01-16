import json

class BIP329_Parser:
    """
    """
    def __init__(self, json_stream):
        self.json_stream = json_stream
        self.entries = []

    def load_entries(self):
        self.entries = []
        try:
            entries = self.json_stream.strip().split('\n')
            for entry in entries:
                try:
                    parsed_entry = json.loads(entry.strip())
                    if self.is_valid_entry(parsed_entry):
                        self.entries.append(parsed_entry)
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {entry.strip()}")
        except Exception as e:
            print(f"Error processing stream: {e}")
        return self.entries

    @staticmethod
    def is_valid_entry(entry):
        required_keys = {'type', 'ref'}
        valid_types = {'tx', 'addr', 'pubkey', 'input', 'output', 'xpub'}

        if not required_keys.issubset(entry.keys()):
            return False

        if 'type' not in entry or entry['type'] not in valid_types:
            return False

        if entry['type'] == 'output':
            if 'spendable' in entry and entry['spendable'] not in {'true', 'false', True, False}:
                return False

        if 'ref' not in entry:
            return False

        if 'label' in entry and not isinstance(entry['label'], str):
            return False

        if 'origin' in entry and not isinstance(entry['origin'], str):
            return False

        return entry


def is_json_file(path):
    """ """
    try:
        with open(path, 'r', encoding='utf-8') as file:
            data = file.read()
            # Attempt to parse the content as JSON
            json.loads(data)
            return True
    except (ValueError, FileNotFoundError):
        pass
    return False

def import_bip329_labels(stream, wallet):
    """
    Import transaction and address labels, and manage coin (UTXO) state according to BIP-329.
    Parameters:
        stream: The stream object containing the BIP-329 formatted data (JSON Lines) to be imported.
        wallet: The current wallet.
    Behavior:
    - The function parses the BIP-329 formatted data located at the specified `path`.
    - It loads the entries from the data, including transaction labels, address labels, and coin information.
    - For each entry, it performs the following actions based on the entry type:
      - If the entry type is "addr" or "tx," it sets labels for transactions and addresses in the wallet.
      - If the entry type is "output," it sets labels for specific transactions and determines whether the associated
        coins should be spendable or frozen. Coins can be frozen by setting the "spendable" attribute to "false" or
        `False`. See also "Coin Management".
    Coin Management:
    - The function also manages coins (UTXOs) by potentially freezing them based on the provided data.
    - Transactions (TXns) are labeled before coin state management.
    - Note that this "output" coin management may overwrite a previous "tx" entry if applicable.
    - In the context of the Electrum export, TXns are exported before coin state information.
    - By default, if no specific information is provided, imported UTXOs are considered spendable (not frozen).
    Note:
    This function is designed to be used with BIP-329 formatted data and a wallet that supports this standard.
    Importing data from other formats *may* not yield the desired results.
    Disclaimer:
    Ensure that you have a backup of your wallet data before using this function, as it may modify labels and coin
    states within your wallet.
    """
    parser = BIP329_Parser(stream)
    entries = parser.load_entries()
    for entry in entries:
        if entry.get('type', '') in ["addr", "tx"]:
            # Set txns and address labels.
            wallet.set_label(entry.get('ref', ''), entry.get('label', ''))
        elif entry.get('type', '') == "output":
            txid, out_idx = entry.get('ref', '').split(":")
            wallet.set_label(txid, entry.get('label', ''))
            # Set spendable or frozen.
            if entry.get("spendable", True) in ["false", False]:
                wallet.set_frozen_state_of_coins(utxos=[entry.get('ref', '')], freeze=True)
            else:
                wallet.set_frozen_state_of_coins(utxos=[entry.get('ref', '')], freeze=False)


def export_bip329_labels(stream, wallet):
    """
    Transactions (TXns) are exported and labeled before coin state information (spendable).
    """
    for key, value in wallet.get_all_labels().items():
        data = {
            "type": "tx" if len(key) == 64 else "addr",
            "ref": key,
            "label": value
        }
        json_line = json.dumps(data, ensure_ascii=False)
        stream.write(f"{json_line}\n")

    for utxo in wallet.get_utxos():
        data = {
            "type": "output",
            "ref": "{}:{}".format(utxo.prevout.txid.hex(), utxo.prevout.out_idx),
            "label": wallet.get_label_for_address(utxo.address),
            "spendable": "true" if not wallet.is_frozen_coin(utxo) else "false"
        }
        json_line = json.dumps(data, ensure_ascii=False)
        stream.write(f"{json_line}\n")
