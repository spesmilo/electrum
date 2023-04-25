import QtQuick 2.6
import QtQuick.Controls 2.0
import QtQuick.Layouts 1.0

import "controls"

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

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        QRScan {
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
