import QtQuick 2.15
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.0

Item {
    id: root

    signal keyEvent(keycode: int, text: string)

    property int padding: 15

    property int keywidth: (root.width - 2 * padding) / 11 - keyhspacing
    property int keyheight: (root.height - 2 * padding) / 4 - keyvspacing
    property int keyhspacing: 4
    property int keyvspacing: 5

    function emitKeyEvent(key) {
        var keycode
        if (key == '<=') {
            keycode = Qt.Key_Backspace
        } else {
            keycode = parseInt(key, 36) - 9 + 0x40 // map char to key code
        }
        keyEvent(keycode, key)
    }

    ColumnLayout {
        id: rootLayout
        x: padding
        y: padding
        width: parent.width - 2*padding
        spacing: keyvspacing
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: keyhspacing
            Repeater {
                model: ['q','w','e','r','t','y','u','i','o','p','<=']
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
                kbd: root
                implicitWidth: keywidth * 5
                implicitHeight: keyheight
            }
            // spacer
            Item { Layout.preferredHeight: 1; Layout.preferredWidth: keywidth / 2 }
        }
    }

}
