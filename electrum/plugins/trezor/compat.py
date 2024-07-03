try:
    # Trezor == 0.13.8
    from trezorlib.messages import RecoveryDeviceType

    RECOVERY_TYPE_SCRAMBLED_WORDS = RecoveryDeviceType.ScrambledWords
    RECOVERY_TYPE_MATRIX = RecoveryDeviceType.Matrix

except ImportError:
    # Trezor >= 0.13.9
    from trezorlib.messages import RecoveryDeviceInputMethod

    RECOVERY_TYPE_SCRAMBLED_WORDS = RecoveryDeviceInputMethod.ScrambledWords
    RECOVERY_TYPE_MATRIX = RecoveryDeviceInputMethod.Matrix
