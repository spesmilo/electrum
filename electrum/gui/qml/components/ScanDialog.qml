import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import org.electrum

import "controls"

// currently not used on android, kept for future use when qt6 camera stops crashing
ElDialog {
    id: scanDialog

    property string error
    property string hint

    signal foundText(data: string)
    signal foundBinary(data: Bytes)

    width: parent.width
    height: parent.height
    padding: 0

    header: null
    topPadding: 0 // dialog needs topPadding override

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
}
