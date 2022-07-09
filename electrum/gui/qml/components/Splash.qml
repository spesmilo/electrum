import QtQuick 2.0

Item {
    property bool toolbar: false

    Rectangle {
        anchors.fill: parent
        color: '#111144'
    }

    Image {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        source: "../../icons/electrum.png"
    }
}
