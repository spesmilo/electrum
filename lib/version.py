ELECTRUM_FTC_VERSION = 'unknown-version'
ELECTRUM_VERSION = '3.0.6'   # version of the client package
PROTOCOL_VERSION = '1.1'     # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet
SEED_PREFIX_2FA  = '101'     # Two-factor authentication
SEED_PREFIX_SW   = '100'     # Segwit wallet

if ELECTRUM_FTC_VERSION is 'unknown-version':
    import subprocess
    import platform
    try:
        cmd = ["git", "describe", "--dirty"]
        if platform.system() is 'Windows':
            cmd = ["cmd", "/c"] + cmd
        result = subprocess.run(cmd, stdout=subprocess.PIPE)
        ELECTRUM_FTC_VERSION = result.stdout.decode('utf-8').strip()
    except Exception:
        pass

def seed_prefix(seed_type):
    if seed_type == 'standard':
        return SEED_PREFIX
    elif seed_type == 'segwit':
        return SEED_PREFIX_SW
    elif seed_type == '2fa':
        return SEED_PREFIX_2FA
