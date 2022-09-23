import QtQuick 2.6
import QtQuick.Controls 2.15

Item {
    id: root

    property alias text: buttonLabel.text
    property alias font: buttonLabel.font

    signal clicked

    implicitWidth: buttonLabel.width + constants.paddingXXLarge
    implicitHeight: buttonLabel.height + constants.paddingXXLarge

    Label {
        id: buttonLabel
        anchors.centerIn: parent
    }

    MouseArea {
        anchors.fill: root
        onClicked: root.clicked()
    }
}
