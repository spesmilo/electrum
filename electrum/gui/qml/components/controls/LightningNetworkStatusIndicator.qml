import QtQuick 2.6

Image {
    id: root

    sourceSize.width: constants.iconSizeMedium
    sourceSize.height: constants.iconSizeMedium

    source: Daemon.currentWallet.lightningNumPeers
                ? '../../../icons/lightning.png'
                : '../../../icons/lightning_disconnected.png'
}
