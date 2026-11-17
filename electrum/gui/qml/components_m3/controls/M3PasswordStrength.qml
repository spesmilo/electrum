import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

// Password strength of the Material 3 GUI: 4 segments (4 dp high, radius 2) and a labelMedium caption in the
// color of the strength. DESIGN-M2-onboarding.md 3.4.
// repeats: components/controls/PasswordStrengthIndicator.qml:5-24 @ e6df7e1c8 (password, strength,
// strengthColor, strengthText, Daemon.passwordStrength and the map 0..3 -> Weak / Medium / Strong / Very Strong).
// Colors: Weak m3.error, Medium m3.tertiary, Strong and Very Strong m3.success; empty segments
// surfaceContainerHighest; no caption while the password is empty.
ColumnLayout {
    id: root
    property string password
    property int strength: 0
    property color strengthColor
    property string strengthText

    onPasswordChanged: checkPasswordStrength(password)

    function checkPasswordStrength() {
        var _strength = Daemon.passwordStrength(password)
        var map = {
            0: [m3.error, qsTranslate('PasswordStrengthIndicator', 'Weak')],
            1: [m3.tertiary, qsTranslate('PasswordStrengthIndicator', 'Medium')],
            2: [m3.success, qsTranslate('PasswordStrengthIndicator', 'Strong')],
            3: [m3.success, qsTranslate('PasswordStrengthIndicator', 'Very Strong')]
        }
        strength = password.length ? _strength + 1 : 0
        strengthText = password.length ? map[_strength][1] : ''
        strengthColor = map[_strength][0]
    }

    // the theme can change while the field is shown: the colors of the map are taken again
    Connections {
        target: m3
        function onDarkChanged() { root.checkPasswordStrength() }
    }

    Component.onCompleted: checkPasswordStrength()

    spacing: m3.space4

    RowLayout {
        Layout.fillWidth: true
        spacing: m3.space4
        Repeater {
            model: 4
            Rectangle {
                required property int index
                Layout.fillWidth: true
                Layout.preferredHeight: 4
                radius: 2
                color: index < root.strength ? root.strengthColor : m3.surfaceContainerHighest
            }
        }
    }

    M3Text {
        Layout.fillWidth: true
        visible: root.strengthText !== ''
        role: 'labelMedium'
        color: root.strengthColor
        text: root.strengthText
    }
}
