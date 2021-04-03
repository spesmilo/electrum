import QtQuick 2.6

Item {
    height: 60

    property alias text: label.text

    Rectangle {
        anchors.fill: parent
        color: '#cccccc'
    }

    Text {
        id: label
        x: 10
        anchors.verticalCenter: parent.verticalCenter
        font.pointSize: 11
        color: '#202020'
    }

    Rectangle {
        x: 10
        width: parent.width - 20
        height: 2
        anchors.topMargin: 0
        anchors.top: label.bottom
        color: '#808080'
    }
}
