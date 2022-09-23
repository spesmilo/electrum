import QtQuick 2.6
import QtQuick.Controls 2.14
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.1

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    property InvoiceParser invoiceParser

    signal manualInput

    parent: Overlay.overlay
    modal: true
    standardButtons: Dialog.Close

    width: parent.width
    height: parent.height

    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    padding: 0

    onClosed: destroy()

    ColumnLayout {
        anchors.fill: parent

        QRScan {
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true

            onFound: invoiceParser.recipient = scanData
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Manual input')
            onClicked: {
                manualInput()
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr('Paste from clipboard')
            onClicked: invoiceParser.recipient = AppController.clipboardToText()
        }
    }

}
