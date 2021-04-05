import QtQuick 2.6
import QtQuick.Controls 2.0

Item {

    property bool toolbar: false
    property string title: 'scan'

    QRScan {
        anchors.top: parent.top
        anchors.bottom: button.top
        width: parent.width
    }

    Button {
        anchors.horizontalCenter: parent.horizontalCenter
        id: button
        anchors.bottom: parent.bottom
        text: 'Cancel'
        onClicked: app.stack.pop()
    }

}
