import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import org.electrum

import "controls"

ElDialog {
    id: scanDialog

    property string error
    property string hint: qsTr('Scan a QR code.')

    signal foundText(data: string)

    width: parent.width
    height: parent.height
    padding: 0

    header: null
    topPadding: app.statusBarHeight

    onAboutToHide: qrscan.stop()

    function doClose() {
        qrscan.stop()
        Qt.callLater(doReject)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        QRScan {
            id: qrscan
            Layout.fillWidth: true
            Layout.fillHeight: true
            hint: scanDialog.hint
            onFoundText: (data) => {
                scanDialog.foundText(data)
            }
        }

        FlatButton {
            id: button
            Layout.fillWidth: true
            text: qsTr('Cancel')
            icon.source: '../../icons/closebutton.png'
            onClicked: doReject()
        }
    }

    onClosed: destroy()
}
