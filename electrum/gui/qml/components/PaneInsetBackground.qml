import QtQuick 2.6
import QtQuick.Controls.Material 2.0

Rectangle {
    Rectangle {
        anchors { left: parent.left; top: parent.top; right: parent.right }
        height: 1
        color: Qt.darker(Material.background, 1.50)
    }
    Rectangle {
        anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
        width: 1
        color: Qt.darker(Material.background, 1.50)
    }
    Rectangle {
        anchors { left: parent.left; bottom: parent.bottom; right: parent.right }
        height: 1
        color: Qt.lighter(Material.background, 1.50)
    }
    Rectangle {
        anchors { right: parent.right; top: parent.top; bottom: parent.bottom }
        width: 1
        color: Qt.lighter(Material.background, 1.50)
    }
    color: Qt.darker(Material.background, 1.15)
    Image {
        source: '../../icons/electrum_lightblue.svg'
        anchors.centerIn: parent
        sourceSize.width: 128
        sourceSize.height: 128
        opacity: 0.1
    }
}
