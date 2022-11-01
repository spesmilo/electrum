import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

Rectangle {
    id: root
    radius: height/2
    implicitWidth: layout.implicitWidth
    implicitHeight: layout.implicitHeight
    color: 'transparent'
    border.color: Material.accentColor

    property alias text: label.text
    property alias font: label.font
    property alias labelcolor: label.color

    property string iconSource

    RowLayout {
        id: layout
        spacing: 0

        Item {
            // spacer
            visible: iconSource
            Layout.preferredWidth: constants.paddingSmall
            Layout.preferredHeight: 1
        }

        Image {
            visible: iconSource
            Layout.preferredWidth: constants.iconSizeSmall
            Layout.preferredHeight: constants.iconSizeSmall
            source: iconSource
        }

        Item {
            // spacer
            visible: iconSource
            Layout.preferredWidth: constants.paddingXXSmall
            Layout.preferredHeight: 1
        }

        Rectangle {
            visible: iconSource
            Layout.preferredHeight: root.height
            Layout.preferredWidth: 1
            color: root.color
            border.color: root.border.color
        }

        Label {
            id: label
            Layout.leftMargin: constants.paddingSmall
            Layout.rightMargin: constants.paddingSmall
            Layout.topMargin: constants.paddingXXSmall
            Layout.bottomMargin: constants.paddingXXSmall
            font.pixelSize: constants.fontSizeXSmall
            color: root.border.color
        }
    }
}
