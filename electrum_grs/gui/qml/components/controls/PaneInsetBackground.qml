import QtQuick 2.6
import QtQuick.Controls.Material 2.0

Rectangle {
    property color baseColor: Material.background
    Rectangle {
        anchors { left: parent.left; top: parent.top; right: parent.right }
        height: 1
        color: Qt.darker(baseColor, 1.50)
    }
    Rectangle {
        anchors { left: parent.left; top: parent.top; bottom: parent.bottom }
        width: 1
        color: Qt.darker(baseColor, 1.50)
    }
    Rectangle {
        anchors { left: parent.left; bottom: parent.bottom; right: parent.right }
        height: 1
        color: Qt.lighter(baseColor, 1.50)
    }
    Rectangle {
        anchors { right: parent.right; top: parent.top; bottom: parent.bottom }
        width: 1
        color: Qt.lighter(baseColor, 1.50)
    }
    color: Qt.darker(baseColor, 1.15)
}
