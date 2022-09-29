import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('LNURL Payment request')

    // property var lnurlData
    property InvoiceParser invoiceParser
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
            text: qsTr('Provider')
        }
        Label {
            text: invoiceParser.lnurlData['domain']
        }
        Label {
            text: qsTr('Description')
        }
        Label {
            text: invoiceParser.lnurlData['metadata_plaintext']
        }
        Label {
            text: invoiceParser.lnurlData['min_sendable_sat'] == invoiceParser.lnurlData['max_sendable_sat']
                    ? qsTr('Amount')
                    : qsTr('Amount range')
        }
        Label {
            text: invoiceParser.lnurlData['min_sendable_sat'] == invoiceParser.lnurlData['max_sendable_sat']
                    ? invoiceParser.lnurlData['min_sendable_sat'] == 0
                        ? qsTr('Unspecified')
                        : invoiceParser.lnurlData['min_sendable_sat']
                    : invoiceParser.lnurlData['min_sendable_sat'] + ' < amount < ' + invoiceParser.lnurlData['max_sendable_sat']
        }

        Button {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Proceed')
            onClicked: {
                invoiceParser.lnurlGetInvoice(invoiceParser.lnurlData['min_sendable_sat'])
                dialog.close()
            }
        }
    }
}
