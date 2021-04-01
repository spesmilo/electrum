import QtQuick 2.0

Item {
    Rectangle {
        anchors.fill: parent
        color: '#111111'
    }

    Image {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        source: "../../icons/electrum.png"
    }
}
