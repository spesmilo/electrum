import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('OTP auth')

    property string otpauth

    // property var lnurlData
    // property InvoiceParser invoiceParser
    // property alias lnurlData: dialog.invoiceParser.lnurlData

    standardButtons: Dialog.Cancel

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    GridLayout {
        columns: 2
        implicitWidth: parent.width

        Label {
            text: qsTr('code')
        }

        TextField {
            id: otpEdit
        }

        Button {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Proceed')
            onClicked: {
                // dialog.close()
                otpauth = otpEdit.text
                dialog.accept()
            }
        }

    }
}
