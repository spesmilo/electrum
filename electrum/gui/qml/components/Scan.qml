import QtQuick 2.6
import QtQuick.Controls 2.0

import org.electrum 1.0

import "controls"

Item {
    id: scanPage
    property string title: qsTr('Scan')

    property bool toolbar: false

    property string scanData
    property var invoiceData: undefined
    property string error

    signal found

    QRScan {
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: parent.width

        onFound: {
            scanPage.scanData = scanData
            var invoice = bitcoin.parse_uri(scanData)
            if (invoice['error']) {
                error = invoice['error']
                console.log(error)
                app.stack.pop()
                return
            }

            invoiceData = invoice
            console.log(invoiceData['address'])
            scanPage.found()
            app.stack.pop()
        }
    }

    Button {
        anchors.horizontalCenter: parent.horizontalCenter
        id: button
        anchors.bottom: parent.bottom
        text: 'Cancel'
        onClicked: app.stack.pop()
    }

    Bitcoin {
        id: bitcoin
    }
}
