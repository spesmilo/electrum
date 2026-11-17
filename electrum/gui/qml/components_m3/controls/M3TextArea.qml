import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Multi-line text input of the Material 3 GUI: an outlined box (radius XS, outline; primary and 2 dp while
// focused) that scrolls its text when it overflows the height given by the layout.
// repeats: components/controls/ElTextArea.qml:12-72 @ e6df7e1c8 (the Flickable around a TextArea with
// ensureVisible() following the cursor, the click below the text focusing it, and the API: text, wrapMode,
// background, font, inputMethodHints, placeholderText, color, topPadding, anyActiveFocus, textChanged).
// Added: `readOnly`, `textArea` (the inner TextArea), `errorText` (outline in m3.error).
Flickable {
    id: root

    property alias text: edit.text
    property alias wrapMode: edit.wrapMode
    property alias background: rootpane.background
    property alias font: edit.font
    property alias inputMethodHints: edit.inputMethodHints
    property string placeholderText
    property alias color: edit.color
    property alias topPadding: rootpane.topPadding
    property alias readOnly: edit.readOnly
    property alias textArea: edit
    property string errorText
    readonly property bool anyActiveFocus: activeFocus || edit.activeFocus

    implicitHeight: 120
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
        padding: m3.space4
        topPadding: m3.space8
        background: Item {}
        TextArea {
            id: edit
            width: parent.width
            focus: true
            wrapMode: TextEdit.Wrap
            // the Material TextArea centers its first line in its own 56 px container; without that container
            // (background replaced) its top padding is negative, the first line starts above the box and
            // ensureVisible() scrolls it down as soon as the cursor appears: the text jumped on the first key
            topPadding: 0
            font.pixelSize: m3.textStyle('bodyLarge').size
            color: m3.surfaceOn
            onCursorRectangleChanged: root.ensureVisible(cursorRectangle)
            background: Rectangle {
                color: 'transparent'
            }

            // the hint of the empty field (classic: placeholderText while the text is empty), drawn where the
            // first line of the text goes: the Material placeholder of a TextArea without its container sits
            // above that line and, on focus, shrinks into a floating label for a border this box does not have
            Text {
                x: edit.leftPadding
                y: edit.topPadding
                width: edit.width - edit.leftPadding - edit.rightPadding
                visible: edit.length === 0 && edit.preeditText === ''
                text: root.placeholderText
                font: edit.font
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                textFormat: Text.PlainText
                renderType: edit.renderType
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

    // the outline does not scroll with the text: a child of the Flickable itself, not of its content
    Rectangle {
        parent: root
        anchors.fill: parent
        z: 1
        color: 'transparent'
        radius: m3.radiusXS
        border.width: root.anyActiveFocus || root.errorText !== '' ? 2 : 1
        border.color: root.errorText !== ''
            ? m3.error
            : root.anyActiveFocus ? m3.primary : m3.outline
    }
}
