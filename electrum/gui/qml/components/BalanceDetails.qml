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

    property bool _is2fa: Daemon.currentWallet && Daemon.currentWallet.walletType == '2fa'

    function enableLightning() {
        var dialog = app.messageDialog.createObject(rootItem,
                {'text': qsTr('Enable Lightning for this wallet?'), 'yesno': true})
        dialog.yesClicked.connect(function() {
            Daemon.currentWallet.enableLightning()
        })
        dialog.open()
    }

    function deleteWallet() {
        var dialog = app.messageDialog.createObject(rootItem,
                {'text': qsTr('Really delete this wallet?'), 'yesno': true})
        dialog.yesClicked.connect(function() {
            Daemon.checkThenDeleteWallet(Daemon.currentWallet)
        })
        dialog.open()
    }

    function changePassword() {
        // trigger dialog via wallet (auth then signal)
        Daemon.startChangePassword()
    }

    function importAddressesKeys() {
        var dialog = importAddressesKeysDialog.createObject(rootItem)
        dialog.open()
    }

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
                            visible: !Daemon.currentWallet.totalBalance.isEmpty
                            Layout.preferredWidth: 1; Layout.preferredHeight: 1
                        }
                        Label {
                            visible: !Daemon.currentWallet.totalBalance.isEmpty
                            text: qsTr('Total')
                        }
                        FormattedAmount {
                            visible: !Daemon.currentWallet.totalBalance.isEmpty
                            amount: Daemon.currentWallet.totalBalance
                        }

                        Rectangle {
                            visible: !Daemon.currentWallet.lightningBalance.isEmpty
                            Layout.preferredWidth: constants.iconSizeXSmall
                            Layout.preferredHeight: constants.iconSizeXSmall
                            color: constants.colorPiechartLightning
                        }
                        Label {
                            visible: !Daemon.currentWallet.lightningBalance.isEmpty
                            text: qsTr('Lightning')

                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.lightningBalance
                            visible: !Daemon.currentWallet.lightningBalance.isEmpty
                        }

                        Rectangle {
                            visible: !Daemon.currentWallet.lightningBalance.isEmpty || !Daemon.currentWallet.frozenBalance.isEmpty
                            Layout.preferredWidth: constants.iconSizeXSmall
                            Layout.preferredHeight: constants.iconSizeXSmall
                            color: constants.colorPiechartOnchain
                        }
                        Label {
                            visible: !Daemon.currentWallet.lightningBalance.isEmpty || !Daemon.currentWallet.frozenBalance.isEmpty
                            text: qsTr('On-chain')

                        }
                        FormattedAmount {
                            amount: Daemon.currentWallet.confirmedBalance
                            visible: !Daemon.currentWallet.lightningBalance.isEmpty || !Daemon.currentWallet.frozenBalance.isEmpty
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
                }
            }
        }
	
        ButtonContainer {
            Layout.fillWidth: true
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Lightning swap');
                visible: Daemon.currentWallet.lightningCanSend.satsInt > 0 || Daemon.currentWallet.lightningCanReceive.satInt > 0
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
