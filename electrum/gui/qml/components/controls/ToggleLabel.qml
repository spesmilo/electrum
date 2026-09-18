import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

import "."

Label {
    id: root
    property bool collapsed: true
    property string labelText

    text: (collapsed ? '▷' : '▽') + ' ' + labelText

    TapHandler {
        onTapped: {
            root.collapsed = !root.collapsed
        }
    }
}
