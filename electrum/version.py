ELECTRUM_FTC_VERSION = 'unknown-version'
ELECTRUM_VERSION = '3.3.8'   # version of the client package
APK_VERSION = '3.3.8.0'      # read by buildozer.spec

PROTOCOL_VERSION = '1.4'     # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX        = '01'      # Standard wallet
SEED_PREFIX_SW     = '100'     # Segwit wallet
SEED_PREFIX_2FA    = '101'     # Two-factor authentication
SEED_PREFIX_2FA_SW = '102'     # Two-factor auth, using segwit

if ELECTRUM_FTC_VERSION == 'unknown-version':
    import subprocess
    import platform
    cmd = ["git", "describe", "--always", "--dirty"]
    if platform.system() == 'Windows':
        cmd = ["cmd", "/c"] + cmd
    result = subprocess.run(cmd, stdout=subprocess.PIPE)
    ELECTRUM_FTC_VERSION = result.stdout.decode('utf-8').strip()
    if ELECTRUM_FTC_VERSION == "":
        raise Exception("cannot extract version string from git")

def seed_prefix(seed_type):
    if seed_type == 'standard':
        return SEED_PREFIX
    elif seed_type == 'segwit':
        return SEED_PREFIX_SW
    elif seed_type == '2fa':
        return SEED_PREFIX_2FA
    elif seed_type == '2fa_segwit':
        return SEED_PREFIX_2FA_SW
