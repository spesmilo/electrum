import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.1

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    property alias amount: amountBtc.text
    property alias description: message.text
    property alias expiry: expires.currentValue


    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Close

    implicitWidth: parent.width
    height: parent.height

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    GridLayout {
        id: form
        width: parent.width
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
            text: qsTr('Request')
            wrapMode: Text.WordWrap
            Layout.rightMargin: constants.paddingXLarge
        }

        BtcField {
            id: amountBtc
            fiatfield: amountFiat
            Layout.preferredWidth: parent.width /3
        }

        Label {
            text: Config.baseUnit
            color: Material.accentColor
        }

        Item { width: 1; height: 1; Layout.fillWidth: true }

        Item { visible: Daemon.fx.enabled; width: 1; height: 1 }

        FiatField {
            id: amountFiat
            btcfield: amountBtc
            visible: Daemon.fx.enabled
            Layout.preferredWidth: parent.width /3
        }

        Label {
            visible: Daemon.fx.enabled
            text: Daemon.fx.fiatCurrency
            color: Material.accentColor
        }

        Item { visible: Daemon.fx.enabled; width: 1; height: 1; Layout.fillWidth: true }

        Label {
            text: qsTr('Expires after')
            Layout.fillWidth: false
        }

        ElComboBox {
            id: expires
            Layout.columnSpan: 2

            textRole: 'text'
            valueRole: 'value'

            model: ListModel {
                id: expiresmodel
                Component.onCompleted: {
                    // we need to fill the model like this, as ListElement can't evaluate script
                    expiresmodel.append({'text': qsTr('10 minutes'), 'value': 10*60})
                    expiresmodel.append({'text': qsTr('1 hour'), 'value': 60*60})
                    expiresmodel.append({'text': qsTr('1 day'), 'value': 24*60*60})
                    expiresmodel.append({'text': qsTr('1 week'), 'value': 7*24*60*60})
                    expiresmodel.append({'text': qsTr('1 month'), 'value': 31*24*60*60})
                    expiresmodel.append({'text': qsTr('Never'), 'value': 0})
                    expires.currentIndex = 0
                }
            }
        }

        Item { width: 1; height: 1; Layout.fillWidth: true }

        Button {
            Layout.columnSpan: 4
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Create Request')
            icon.source: '../../icons/qrcode.png'
            onClicked: {
                accept()
            }
        }
    }

}
