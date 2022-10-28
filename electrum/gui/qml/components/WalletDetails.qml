import QtQuick 2.6
import QtQuick.Layouts 1.5
import QtQuick.Controls 2.12
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Item {
    id: root
    clip: true
    Layout.fillWidth: true
    implicitHeight: 0

    function open() {
        state = 'opened'
    }
    function close() {
        state = ''
    }
    function toggle() {
        if (state == 'opened')
            state = ''
        else
            state = 'opened'
    }

    states: [
        State {
            name: 'opened'
            PropertyChanges { target: root; implicitHeight: detailsPane.height }
        }
    ]

    transitions: [
        Transition {
            from: ''
            to: 'opened'
            NumberAnimation { target: root; properties: 'implicitHeight'; duration: 200 }
        },
        Transition {
            from: 'opened'
            to: ''
            NumberAnimation { target: root; properties: 'implicitHeight'; duration: 200 }
        }
    ]

    Pane {
        id: detailsPane
        width: parent.width
        anchors.bottom: parent.bottom
        padding: 0
        background: Rectangle {
            color: Material.dialogColor
        }

        ColumnLayout {
            width: parent.width

            GridLayout {
                id: detailsLayout
                visible: Daemon.currentWallet
                rowSpacing: constants.paddingSmall
                Layout.preferredWidth: parent.width
                Layout.margins: constants.paddingXLarge

                columns: 2

                // Label {
                //     text: qsTr('Wallet')
                //     color: Material.accentColor
                //     font.pixelSize: constants.fontSizeLarge
                // }
                Image {
                    source: '../../icons/wallet.png'
                    Layout.preferredWidth: constants.iconSizeLarge
                    Layout.preferredHeight: constants.iconSizeLarge
                }
                Label {
                    Layout.fillWidth: true
                    text: Daemon.currentWallet.name;
                    font.bold: true;
                    font.pixelSize: constants.fontSizeXLarge
                }

                RowLayout {
                    Layout.columnSpan: 2
                    Tag {
                        text: Daemon.currentWallet.walletType
                        font.pixelSize: constants.fontSizeSmall
                        font.bold: true
                        iconSource: '../../../icons/wallet.png'
                    }
                    Tag {
                        text: Daemon.currentWallet.txinType
                        font.pixelSize: constants.fontSizeSmall
                        font.bold: true
                    }
                    Tag {
                        text: qsTr('HD')
                        visible: Daemon.currentWallet.isDeterministic
                        font.pixelSize: constants.fontSizeSmall
                        font.bold: true
                    }
                    Tag {
                        text: qsTr('Watch only')
                        visible: Daemon.currentWallet.isWatchOnly
                        font.pixelSize: constants.fontSizeSmall
                        font.bold: true
                        iconSource: '../../../icons/eye1.png'
                    }
                    Tag {
                        text: qsTr('Encrypted')
                        visible: Daemon.currentWallet.isEncrypted
                        font.pixelSize: constants.fontSizeSmall
                        font.bold: true
                        iconSource: '../../../icons/key.png'
                    }
                    Tag {
                        text: qsTr('HW')
                        visible: Daemon.currentWallet.isHardware
                        font.pixelSize: constants.fontSizeSmall
                        font.bold: true
                        iconSource: '../../../icons/seed.png'
                    }
                    Tag {
                        text: qsTr('Lightning')
                        visible: Daemon.currentWallet.isLightning
                        font.pixelSize: constants.fontSizeSmall
                        font.bold: true
                        iconSource: '../../../icons/lightning.png'
                    }
                    Tag {
                        text: qsTr('Seed')
                        visible: Daemon.currentWallet.hasSeed
                        font.pixelSize: constants.fontSizeSmall
                        font.bold: true
                        iconSource: '../../../icons/seed.png'
                    }
                }

           }

            RowLayout {
                Layout.fillWidth: true
                FlatButton {
                    text: qsTr('More details')
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                }
                FlatButton {
                    text: qsTr('Switch wallet')
                    Layout.fillWidth: true
                    icon.source: '../../icons/file.png'
                    Layout.preferredWidth: 1
                }
            }
        }
    }

}
