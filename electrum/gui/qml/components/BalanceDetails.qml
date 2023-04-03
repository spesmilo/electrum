import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem
    objectName: 'BalanceDetails'

    padding: 0

    ColumnLayout {
        id: rootLayout
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            contentHeight: flickableRoot.height
            clip:true
            interactive: height < contentHeight

            Pane {
                id: flickableRoot
                width: parent.width
                padding: constants.paddingLarge

                ColumnLayout {
                    width: parent.width
                    spacing: constants.paddingLarge

                    InfoTextArea {
                        Layout.fillWidth: true
                        Layout.bottomMargin: constants.paddingLarge
                        visible: Daemon.currentWallet.synchronizing || Network.server_status != 'connected'
                        text: Daemon.currentWallet.synchronizing
                                  ? qsTr('Your wallet is not synchronized. The displayed balance may be inaccurate.')
                                  : qsTr('Your wallet is not connected to an Electrum server. The displayed balance may be outdated.')
                        iconStyle: InfoTextArea.IconStyle.Warn
                    }

                    Heading {
                        text: qsTr('Wallet balance')
                    }

                    Piechart {
                        id: piechart
                        visible: Daemon.currentWallet.totalBalance.satsInt > 0
                        Layout.preferredWidth: parent.width
                        implicitHeight: 220 // TODO: sane value dependent on screen
                        innerOffset: 6
                        function updateSlices() {
                            var totalB = Daemon.currentWallet.totalBalance.satsInt
                            var onchainB = Daemon.currentWallet.confirmedBalance.satsInt
                            var frozenB = Daemon.currentWallet.frozenBalance.satsInt
                            var lnB = Daemon.currentWallet.lightningBalance.satsInt
                            piechart.slices = [
                                { v: lnB/totalB, color: constants.colorPiechartLightning, text: 'Lightning' },
                                { v: (onchainB-frozenB)/totalB, color: constants.colorPiechartOnchain, text: 'On-chain' },
                                { v: frozenB/totalB, color: constants.colorPiechartFrozen, text: 'On-chain (frozen)' },
                            ]
                        }
                    }

                    GridLayout {
                        Layout.alignment: Qt.AlignHCenter
                        visible: Daemon.currentWallet
                        columns: 3
                        Item {
                            Layout.preferredWidth: 1; Layout.preferredHeight: 1
                        }
                        Label {
                            text: qsTr('Total')
                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.totalBalance
                        }

                        Rectangle {
                            visible: Daemon.currentWallet.isLightning
                            Layout.preferredWidth: constants.iconSizeXSmall
                            Layout.preferredHeight: constants.iconSizeXSmall
                            color: constants.colorPiechartLightning
                        }
                        Label {
                            visible: Daemon.currentWallet.isLightning
                            text: qsTr('Lightning')

                        }
                        FormattedAmount {
                            visible: Daemon.currentWallet.isLightning
                            amount: Daemon.currentWallet.lightningBalance
                        }

                        Rectangle {
                            visible: Daemon.currentWallet.isLightning || !Daemon.currentWallet.frozenBalance.isEmpty
                            Layout.preferredWidth: constants.iconSizeXSmall
                            Layout.preferredHeight: constants.iconSizeXSmall
                            color: constants.colorPiechartOnchain
                        }
                        Label {
                            visible: Daemon.currentWallet.isLightning || !Daemon.currentWallet.frozenBalance.isEmpty
                            text: qsTr('On-chain')

                        }
                        FormattedAmount {
                            visible: Daemon.currentWallet.isLightning || !Daemon.currentWallet.frozenBalance.isEmpty
                            amount: Daemon.currentWallet.confirmedBalance
                        }

                        Rectangle {
                            visible: !Daemon.currentWallet.frozenBalance.isEmpty
                            Layout.preferredWidth: constants.iconSizeXSmall
                            Layout.preferredHeight: constants.iconSizeXSmall
                            color: constants.colorPiechartFrozen
                        }
                        Label {
                            visible: !Daemon.currentWallet.frozenBalance.isEmpty
                            text: qsTr('Frozen')
                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.frozenBalance
                            visible: !Daemon.currentWallet.frozenBalance.isEmpty
                        }
                    }

                    Heading {
                        text: qsTr('Lightning Liquidity')
                        visible: Daemon.currentWallet.isLightning
                    }
                    GridLayout {
                        Layout.alignment: Qt.AlignHCenter
                        visible: Daemon.currentWallet && Daemon.currentWallet.isLightning
                        columns: 2
                        Label {
                            text: qsTr('Can send')
                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.lightningCanSend
                        }
                        Label {
                            text: qsTr('Can receive')
                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.lightningCanReceive
                        }
                    }
                }
            }
        }
	
        ButtonContainer {
            Layout.fillWidth: true
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Lightning swap');
                visible: Daemon.currentWallet.isLightning
                enabled: Daemon.currentWallet.lightningCanSend.satsInt > 0 || Daemon.currentWallet.lightningCanReceive.satInt > 0
                icon.source: Qt.resolvedUrl('../../icons/update.png')
                onClicked: {
                    var swaphelper = app.swaphelper.createObject(app)
                    swaphelper.swapStarted.connect(function() {
                        var dialog = swapProgressDialog.createObject(app, { swaphelper: swaphelper })
                        dialog.open()
                    })
                    var dialog = swapDialog.createObject(rootItem, { swaphelper: swaphelper })
                    dialog.open()
                }
            }

            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Open Channel')
                visible: Daemon.currentWallet.isLightning
                enabled: Daemon.currentWallet.confirmedBalance.satsInt > 0
                onClicked: {
                    var dialog = openChannelDialog.createObject(rootItem)
                    dialog.open()
                }
                icon.source: '../../icons/lightning.png'
            }

        }

    }

    Component {
        id: swapDialog
        SwapDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: swapProgressDialog
        SwapProgressDialog {
            onClosed: destroy()
        }
    }

    Component {
        id: openChannelDialog
        OpenChannelDialog {
            onClosed: destroy()
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onBalanceChanged() {
            piechart.updateSlices()
        }
    }

    Component.onCompleted: {
        piechart.updateSlices()
    }

}
