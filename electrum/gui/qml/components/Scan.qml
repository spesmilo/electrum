import QtQuick 2.6
import QtQuick.Controls 2.0

Item {
    id: scanPage
    property string title: qsTr('Scan')

    property bool toolbar: false

    property string scanData

    signal found

    QRScan {
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        width: parent.width

        onFound: {
            scanPage.scanData = scanData
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

}
