import QtQuick 2.6
import QtQuick.Layouts 1.5
import QtQuick.Controls 2.12
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Item {
    id: root
    clip: true
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
            id: rootLayout
            width: parent.width
            spacing: constants.paddingXLarge

            GridLayout {
                visible: Daemon.currentWallet
                rowSpacing: constants.paddingSmall
                Layout.preferredWidth: parent.width
                Layout.topMargin: constants.paddingXLarge

                columns: 2

                RowLayout {
                    Layout.columnSpan: 2
                    Layout.alignment: Qt.AlignHCenter
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

            TextHighlightPane {
                Layout.alignment: Qt.AlignHCenter
                GridLayout {
                    columns: 3

                    Label {
                        font.pixelSize: constants.fontSizeXLarge
                        text: qsTr('Balance:')
                        color: Material.accentColor
                    }

                    Label {
                        font.pixelSize: constants.fontSizeXLarge
                        font.family: FixedFont
                        text: Config.formatSats(Daemon.currentWallet.totalBalance)
                    }
                    Label {
                        font.pixelSize: constants.fontSizeXLarge
                        color: Material.accentColor
                        text: Config.baseUnit
                    }

                    Item {
                        visible: Daemon.fx.enabled
                        Layout.preferredHeight: 1
                        Layout.preferredWidth: 1
                    }
                    Label {
                        Layout.alignment: Qt.AlignRight
                        visible: Daemon.fx.enabled
                        font.pixelSize: constants.fontSizeLarge
                        color: constants.mutedForeground
                        text: Daemon.fx.fiatValue(Daemon.currentWallet.totalBalance, false)
                    }
                    Label {
                        visible: Daemon.fx.enabled
                        font.pixelSize: constants.fontSizeLarge
                        color: constants.mutedForeground
                        text: Daemon.fx.fiatCurrency
                    }
                }
            }

            Piechart {
                id: piechart
                visible: Daemon.currentWallet.totalBalance.satsInt > 0
                Layout.preferredWidth: parent.width
                implicitHeight: 200
                innerOffset: 6
                function updateSlices() {
                    var totalB = Daemon.currentWallet.totalBalance.satsInt
                    var onchainB = Daemon.currentWallet.confirmedBalance.satsInt
                    var frozenB = Daemon.currentWallet.frozenBalance.satsInt
                    var lnB = Daemon.currentWallet.lightningBalance.satsInt
                    piechart.slices = [
                        { v: (onchainB-frozenB)/totalB, color: constants.colorPiechartOnchain, text: 'On-chain' },
                        { v: frozenB/totalB, color: constants.colorPiechartFrozen, text: 'On-chain (frozen)' },
                        { v: lnB/totalB, color: constants.colorPiechartLightning, text: 'Lightning' }
                    ]
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

    Connections {
        target: Daemon.currentWallet
        function onBalanceChanged() {
            piechart.updateSlices()
        }
    }

}
