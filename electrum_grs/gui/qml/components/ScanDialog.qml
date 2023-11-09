import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import "controls"

// currently not used on android, kept for future use when qt6 camera stops crashing
ElDialog {
    id: scanDialog

    property string scanData
    property string error
    property string hint

    signal found

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
            onFound: {
                scanDialog.scanData = scanData
                scanDialog.found()
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
