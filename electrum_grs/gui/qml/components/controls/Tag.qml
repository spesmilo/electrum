import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

Rectangle {
    radius: constants.paddingXSmall
    width: layout.width
    height: layout.height
    color: 'transparent'
    border.color: Material.accentColor

    property alias text: label.text
    property alias font: label.font
    property alias labelcolor: label.color

    RowLayout {
        id: layout

        Label {
            id: label
            Layout.leftMargin: constants.paddingSmall
            Layout.rightMargin: constants.paddingSmall
            Layout.topMargin: constants.paddingXXSmall
            Layout.bottomMargin: constants.paddingXXSmall
            font.pixelSize: constants.fontSizeXSmall
        }
    }
}
