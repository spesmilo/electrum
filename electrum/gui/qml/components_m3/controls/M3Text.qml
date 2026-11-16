import QtQuick
import QtQuick.Controls

// Label with a role of the Material 3 type scale (see M3Theme.typeScale)
Label {
    id: root

    property string role: 'bodyMedium'
    readonly property var _style: m3.textStyle(role)

    color: m3.surfaceOn
    font.pixelSize: _style.size
    font.weight: _style.weight
    font.letterSpacing: _style.tracking
    lineHeightMode: Text.FixedHeight
    lineHeight: _style.line
    verticalAlignment: Text.AlignVCenter
    textFormat: Text.PlainText
}
