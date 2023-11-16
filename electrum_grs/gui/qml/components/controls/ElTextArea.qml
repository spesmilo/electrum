import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

// this component adds (auto)scrolling to the bare TextArea, to make it
// workable if text overflows the available space.
// This unfortunately hides many signals and properties from the TextArea,
// so add signals propagation and property aliases when needed.
Flickable {
    id: root

    property alias text: edit.text
    property alias wrapMode: edit.wrapMode
    property alias background: rootpane.background
    property alias font: edit.font
    property alias inputMethodHints: edit.inputMethodHints
    property alias placeholderText: edit.placeholderText
    property alias color: edit.color

    contentWidth: rootpane.width
    contentHeight: rootpane.height
    clip: true

    boundsBehavior: Flickable.StopAtBounds
    flickableDirection: Flickable.VerticalFlick

    function ensureVisible(r) {
        r.x = r.x + rootpane.leftPadding
        r.y = r.y + rootpane.topPadding
        var w = width - rootpane.leftPadding - rootpane.rightPadding
        var h = height - rootpane.topPadding - rootpane.bottomPadding
        if (contentX >= r.x)
            contentX = r.x
        else if (contentX+w <= r.x+r.width)
            contentX = r.x+r.width-w
        if (contentY >= r.y)
            contentY = r.y
        else if (contentY+h <= r.y+r.height)
            contentY = r.y+r.height-h
    }

    Pane {
        id: rootpane
        width: root.width
        height: Math.max(root.height, edit.height + topPadding + bottomPadding)
        padding: constants.paddingXSmall
        TextArea {
            id: edit
            width: parent.width
            focus: true
            wrapMode: TextEdit.Wrap
            onCursorRectangleChanged: root.ensureVisible(cursorRectangle)
            onTextChanged: root.textChanged()
            background: Rectangle {
                color: 'transparent'
            }
        }
        MouseArea {
            // remaining area clicks focus textarea
            width: parent.width
            anchors.top: edit.bottom
            anchors.bottom: parent.bottom
            onClicked: edit.forceActiveFocus()
        }
    }

}
