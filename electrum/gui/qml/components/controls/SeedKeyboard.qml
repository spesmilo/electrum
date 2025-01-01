import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

Item {
    id: root

    signal keyEvent(keycode: int, text: string)

    property int hpadding: 0
    property int vpadding: 15

    property int keywidth: (root.width - 2 * hpadding) / 10 - keyhspacing
    property int keyheight: (root.height - 2 * vpadding) / 4 - keyvspacing
    property int keyhspacing: 2
    property int keyvspacing: 5

    function emitKeyEvent(key, keycode) {
        keyEvent(keycode, key)
    }

    ColumnLayout {
        id: rootLayout
        x: hpadding
        y: vpadding
        width: parent.width - 2*hpadding
        spacing: keyvspacing
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: keyhspacing
            Repeater {
                model: ['q','w','e','r','t','y','u','i','o','p']
                delegate: SeedKeyboardKey {
                    key: modelData
                    kbd: root
                    implicitWidth: keywidth
                    implicitHeight: keyheight
                }
            }
        }
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: keyhspacing
            Repeater {
                model: ['a','s','d','f','g','h','j','k','l']
                delegate: SeedKeyboardKey {
                    key: modelData
                    kbd: root
                    implicitWidth: keywidth
                    implicitHeight: keyheight
                }
            }
            // spacer
            Item { Layout.preferredHeight: 1; Layout.preferredWidth: keywidth / 2 }
        }
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: keyhspacing
            Repeater {
                model: ['z','x','c','v','b','n','m']
                delegate: SeedKeyboardKey {
                    key: modelData
                    kbd: root
                    implicitWidth: keywidth
                    implicitHeight: keyheight
                }
            }
            // spacer
            Item { Layout.preferredHeight: 1; Layout.preferredWidth: keywidth }
        }
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            SeedKeyboardKey {
                key: ' '
                keycode: Qt.Key_Space
                kbd: root
                implicitWidth: keywidth * 5
                implicitHeight: keyheight
            }
            SeedKeyboardKey {
                key: '<'
                keycode: Qt.Key_Backspace
                kbd: root
                implicitWidth: keywidth
                implicitHeight: keyheight
            }
            // spacer
            Item { Layout.preferredHeight: 1; Layout.preferredWidth: keywidth / 2 }
        }
    }

}
