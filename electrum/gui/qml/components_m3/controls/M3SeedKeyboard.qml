import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// On-screen keyboard for seed words (DESIGN-M2-onboarding.md 3.3, R-O5 a): a panel (surfaceContainer) meant to be
// pinned to the bottom of a page, the full width of the screen, the keys in a column of at most
// m3.maxContentWidth. On top, the strip of suggestions of `target` (an M3SeedField): a tap replaces the last word.
// The keys write `target.text` themselves.
// repeats: classic controls/SeedKeyboard.qml:9-91, SeedKeyboardKey.qml:9-42 and SeedTextArea.qml:101-142
// @ e6df7e1c8 (the rows qwertyuiop / asdfghjkl / zxcvbnm / space and backspace, the half-key offsets, the signal
// keyEvent(keycode, text), the key code of a letter, autoRepeat with a delay of 750 ms and the repeat on a double
// click, keys without focus (a physical keyboard keeps typing into the field), the suggestion tap that replaces
// the last word and adds a space, backspace that drops the last character and the other keys that append).
// Added: the "delete word" key (DESIGN-M2.md finding 5: fixing a word in the middle needs every later word
// deleted, as the field keeps the cursor at the end); the suggestions keep their height while empty, so the keys
// do not jump; key height `keyHeight` (48, the page sets 40 on a low screen).
Rectangle {
    id: root

    property Item target
    property int keyHeight: 48

    signal keyEvent(int keycode, string text)

    readonly property int _hgap: m3.space4
    readonly property int _vgap: m3.space8
    readonly property int _side: m3.space4
    readonly property real _columnWidth: Math.min(width - 2 * _side, m3.maxContentWidth)
    readonly property real _keyWidth: (_columnWidth - 9 * _hgap) / 10

    color: m3.surfaceContainer
    implicitHeight: layout.implicitHeight + m3.space8

    onKeyEvent: (keycode, text) => {
        if (!target)
            return
        if (keycode == Qt.Key_Backspace) {
            if (target.text.length > 0)
                target.text = target.text.substring(0, target.text.length-1)
        } else {
            target.text = target.text + text
        }
    }

    function _deleteWord() {
        if (target)
            target.text = target.text.replace(/\S*\s*$/, '')
    }

    ColumnLayout {
        id: layout
        anchors.horizontalCenter: parent.horizontalCenter
        y: 0
        width: root._columnWidth
        spacing: root._vgap

        // suggestions
        Flickable {
            Layout.fillWidth: true
            Layout.preferredHeight: 48
            flickableDirection: Flickable.HorizontalFlick
            boundsBehavior: Flickable.StopAtBounds
            contentWidth: suggestionsRow.width
            interactive: contentWidth > width
            clip: true

            Row {
                id: suggestionsRow
                anchors.verticalCenter: parent.verticalCenter
                spacing: m3.space8

                Repeater {
                    model: root.target ? root.target.suggestions : []
                    M3Chip {
                        required property string modelData
                        focusPolicy: Qt.NoFocus
                        text: modelData
                        onClicked: {
                            var words = root.target.text.split(' ')
                            words.pop()
                            words.push(modelData)
                            root.target.text = words.join(' ') + ' '
                        }
                    }
                }
            }
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: root._hgap
            Repeater {
                model: ['q','w','e','r','t','y','u','i','o','p']
                delegate: SeedKey { required property string modelData; key: modelData }
            }
        }
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: root._hgap
            Repeater {
                model: ['a','s','d','f','g','h','j','k','l']
                delegate: SeedKey { required property string modelData; key: modelData }
            }
            // spacer
            Item { Layout.preferredHeight: 1; Layout.preferredWidth: root._keyWidth / 2 }
        }
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: root._hgap
            Repeater {
                model: ['z','x','c','v','b','n','m']
                delegate: SeedKey { required property string modelData; key: modelData }
            }
            // spacer
            Item { Layout.preferredHeight: 1; Layout.preferredWidth: root._keyWidth }
        }
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: root._hgap
            SeedKey {
                widthInKeys: 2
                special: true
                icon.source: Qt.resolvedUrl('../../../icons/m3/backspace.png')
                label: qsTr('word')
                onClicked: root._deleteWord()
                onDoubleClicked: root._deleteWord()
            }
            SeedKey {
                key: ' '
                keycode: Qt.Key_Space
                widthInKeys: 5
            }
            SeedKey {
                key: '<'
                keycode: Qt.Key_Backspace
                widthInKeys: 2
                special: true
                icon.source: Qt.resolvedUrl('../../../icons/m3/backspace.png')
            }
        }
    }

    // one key: a letter (`key`), or an icon and an optional `label` (special keys on secondaryContainer)
    component SeedKey: AbstractButton {
        id: k

        property string key
        property int keycode: -1
        property real widthInKeys: 1
        property bool special: false
        property string label

        function emitKeyEvent() {
            if (key === '')
                return
            if (keycode == -1) {
                keycode = parseInt(key, 36) - 9 + 0x40 // map a-z char to key code
            }
            root.keyEvent(keycode, key)
        }

        implicitWidth: root._keyWidth * widthInKeys + root._hgap * (Math.ceil(widthInKeys) - 1)
        implicitHeight: root.keyHeight
        focusPolicy: Qt.NoFocus
        autoRepeat: true
        autoRepeatDelay: 750
        padding: 0

        onClicked: {
            emitKeyEvent()
        }

        // send keyevent again, otherwise it is ignored
        onDoubleClicked: {
            emitKeyEvent()
        }

        background: Rectangle {
            radius: m3.radiusS
            color: k.special ? m3.secondaryContainer : m3.surfaceContainerHighest
            Rectangle {
                anchors.fill: parent
                radius: parent.radius
                visible: k.pressed
                color: Qt.rgba(m3.surfaceOn.r, m3.surfaceOn.g, m3.surfaceOn.b, m3.statePressed)
            }
        }

        contentItem: Item {
            Row {
                anchors.centerIn: parent
                spacing: m3.space4
                M3Icon {
                    anchors.verticalCenter: parent.verticalCenter
                    visible: k.icon.source != ''
                    size: 20
                    source: k.icon.source
                    color: m3.secondaryContainerOn
                }
                M3Text {
                    anchors.verticalCenter: parent.verticalCenter
                    visible: text !== ''
                    role: k.label !== '' ? 'labelLarge' : 'titleMedium'
                    color: k.special ? m3.secondaryContainerOn : m3.surfaceOn
                    text: k.label !== '' ? k.label : (k.icon.source != '' ? '' : k.key.trim())
                }
            }
        }
    }
}
