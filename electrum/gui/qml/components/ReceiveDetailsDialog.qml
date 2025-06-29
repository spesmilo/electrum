import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQml.Models

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('Create Invoice')
    iconSource: Qt.resolvedUrl('../../icons/tab_receive.png')

    property alias amount: amountBtc.text
    property alias description: message.text
    property alias expiry: expires.currentValue
    property bool isLightning: false

    padding: 0

    ColumnLayout {
        width: parent.width

        GridLayout {
            id: form
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge

            rowSpacing: constants.paddingSmall
            columnSpacing: constants.paddingSmall
            columns: 4


            Label {
                text: qsTr('Message')
            }

            TextField {
                id: message
                placeholderText: qsTr('Description of payment request')
                Layout.columnSpan: 3
                Layout.fillWidth: true
            }

            Label {
                text: qsTr('Amount')
                wrapMode: Text.WordWrap
                Layout.rightMargin: constants.paddingXLarge
            }

            BtcField {
                id: amountBtc
                fiatfield: amountFiat
                Layout.fillWidth: true
            }

            Label {
                Layout.columnSpan: 2
                Layout.rightMargin: constants.paddingXLarge
                text: Config.baseUnit
                color: Material.accentColor
            }

            Item { visible: Daemon.fx.enabled; width: 1; height: 1 }

            FiatField {
                id: amountFiat
                Layout.fillWidth: true
                btcfield: amountBtc
                visible: Daemon.fx.enabled
            }

            Label {
                Layout.columnSpan: 2
                Layout.rightMargin: constants.paddingXLarge
                visible: Daemon.fx.enabled
                text: Daemon.fx.fiatCurrency
                color: Material.accentColor
            }

            Label {
                text: qsTr('Expires after')
                Layout.fillWidth: false
            }

            RequestExpiryComboBox {
                id: expires
                Layout.columnSpan: 3
            }
        }

        GridLayout {
            width: parent.width
	    columns: 2

            FlatButton {
                Layout.fillWidth: true
                text: qsTr('Onchain')
                icon.source: '../../icons/bitcoin.png'
                onClicked: { dialog.isLightning = false; doAccept() }
            }
            FlatButton {
                Layout.fillWidth: true
                enabled: Daemon.currentWallet.isLightning && (Daemon.currentWallet.lightningCanReceive.satsInt
                            > amountBtc.textAsSats.satsInt || Daemon.currentWallet.canGetZeroconfChannel)
                text: qsTr('Lightning')
                icon.source: '../../icons/lightning.png'
                onClicked: {
                    if (Daemon.currentWallet.lightningCanReceive.satsInt > amountBtc.textAsSats.satsInt) {
                        // can receive on existing channel
                        dialog.isLightning = true
                        doAccept()
                    } else if (Daemon.currentWallet.canGetZeroconfChannel && amountBtc.textAsSats.satsInt
                                >= Daemon.currentWallet.minChannelFunding.satsInt) {
                        // ask for confirmation of zeroconf channel to prevent fee surprise
                        var confirmdialog = app.messageDialog.createObject(dialog, {
                            title: qsTr('Confirm just-in-time channel'),
                            text: [qsTr('Receiving this payment will purchase a Lightning channel from your service provider.'),
                                   qsTr('Fees will be deducted from the payment.'),
                                   qsTr('Do you want to continue?')].join(' '),
                            yesno: true
                        })
                        confirmdialog.accepted.connect(function () {
                            dialog.isLightning = true
                            doAccept()
                        })
                        confirmdialog.open()
                    } else {
                        // show error that amnt > 200k is necessary to get zeroconf channel
                        var confirmdialog = app.messageDialog.createObject(dialog, {
                            title: qsTr("Amount too low"),
                            text: [qsTr("You don't have channels with enough inbound liquidity to receive this payment."),
                                   qsTr("Request at least %1 to open a channel just-in-time.").arg(
                                       Config.formatSats(Daemon.currentWallet.minChannelFunding.satsInt, true))].join(' ')
                        })
                        confirmdialog.open()
                    }
                    // can't get zeroconf channel and doesn't have enough inbound liquidity
                }
            }
        }
    }

}
