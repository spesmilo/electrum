Satochip 2-Factor-Authentication (2FA)
=================================================================================

Satochip-2FA is an optional plugin that allows to use 2-Factor-Authentication in conjonction with the Satochip hardware wallet. When enabled, transaction requests are sent to an app on a second device for approval before signing them with the Satochip. For security, the 2FA can only be enabled during initial setup and cannot be disabled once activated! Be sure to keep a copy of the 2FA key in a safe location. 

​When enabled, a secret key is shared via a qr-code between the satochip and a second device (currently, only Android). The app then regularly polls the Electrum server for new transaction proposals. These transaction candidates are then parsed and displayed on the second device. If approved, a cryptographic code is sent back to securely and uniquely approve the transaction so that the satochip can sign it.


