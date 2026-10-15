import QtQuick
import QtQuick.Layouts

ButtonContainer {
    id: root
    separatorColor: constants.darkerDialogBackground
    background: Rectangle {
        color: "transparent"
    }
    headerComponent: Component {
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 2
            Layout.leftMargin: constants.paddingSmall
            Layout.rightMargin: constants.paddingSmall
            color: root.separatorColor
        }
    }
}
