import QtQuick 2.6

import org.electrum 1.0

Item {
    id: root
    visible: Config.useGossip
    implicitWidth: constants.iconSizeMedium
    implicitHeight: constants.iconSizeMedium

    property int gossipProgress: Network.gossipInfo.db_channels
        ? (100 * Network.gossipInfo.db_channels / (Network.gossipInfo.unknown_channels + Network.gossipInfo.db_channels))
        : 0

    Image {
        sourceSize.width: root.implicitWidth
        sourceSize.height: root.implicitHeight

        source: '../../../icons/lightning.png'
    }
    Image {
        sourceSize.width: root.implicitWidth
        sourceSize.height: root.implicitHeight
        fillMode: Image.Pad
        horizontalAlignment: Image.AlignLeft
        verticalAlignment: Image.AlignTop

        source: '../../../icons/lightning_disconnected.png'

        height: constants.iconSizeMedium * (100 - gossipProgress) / 100
    }
}
