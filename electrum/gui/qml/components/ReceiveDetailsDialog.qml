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
                enabled: Daemon.currentWallet.isLightning && Daemon.currentWallet.lightningCanReceive.satsInt > amountBtc.textAsSats.satsInt
                text: qsTr('Lightning')
                icon.source: '../../icons/lightning.png'
                onClicked: { dialog.isLightning = true; doAccept() }
            }
        }
    }

}
