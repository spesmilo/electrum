import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1
import QtQuick.Controls.Material 2.0

Rectangle {
    id: item

    property bool warning
    property bool error
    property string text

    color: "transparent"
    border.color: error ? "red" : warning ? "yellow" : Material.accentColor
    border.width: 1
    height: text.height + 2* 16
    radius: 8

    Text {
        id: text
        width: item.width - 2* 16
        x: 16
        y: 16

        color: item.border.color
        text: item.text
        wrapMode: Text.Wrap
    }

}
