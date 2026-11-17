import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

// Password field of the Material 3 GUI: an outlined text field with the reveal ("eye") button inside on the
// right, and a supporting or error text below (as M3TextField). DESIGN-M2-onboarding.md 3.4.
// repeats: components/controls/PasswordField.qml:5-37 @ e6df7e1c8 (text, tf, echoMode, placeholderText,
// showReveal, accepted(), the input method hints, the minimum width of 16 characters, the toggle of echoMode).
// Added: `field` (the TextField, as M3TextField; `tf` is kept for screens carried over from the classic),
// `label` (= placeholderText, the floating label), `supportingText`, `errorText`.
ColumnLayout {
    id: root
    property alias text: password_tf.text
    property alias tf: password_tf
    property alias field: password_tf
    property alias echoMode: password_tf.echoMode
    property alias placeholderText: password_tf.placeholderText
    property alias label: password_tf.placeholderText
    property bool showReveal: true
    property string supportingText
    property string errorText

    signal accepted

    spacing: m3.space4

    TextField {
        id: password_tf
        echoMode: TextInput.Password
        inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoAutoUppercase | Qt.ImhPreferLowercase
        Layout.fillWidth: true
        Layout.minimumWidth: fontMetrics.advanceWidth('X') * 16
        Material.containerStyle: Material.Outlined
        Material.accent: root.errorText !== '' ? m3.error : m3.primary
        font.pixelSize: m3.textStyle('bodyLarge').size
        color: m3.surfaceOn
        rightPadding: root.showReveal ? revealButton.width + m3.space4 : leftPadding
        onAccepted: root.accepted()

        M3IconButton {
            id: revealButton
            visible: root.showReveal
            enabled: root.showReveal
            anchors.right: parent.right
            anchors.rightMargin: m3.space4
            anchors.verticalCenter: parent.verticalCenter
            focusPolicy: Qt.NoFocus
            tooltip: password_tf.echoMode == TextInput.Password ? qsTr('Show password') : qsTr('Hide password')
            icon.source: Qt.resolvedUrl(password_tf.echoMode == TextInput.Password
                ? '../../../icons/m3/visibility.png'
                : '../../../icons/m3/visibility_off.png')
            onClicked: {
                password_tf.echoMode = password_tf.echoMode == TextInput.Password ? TextInput.Normal : TextInput.Password
            }
        }
    }

    M3Text {
        Layout.fillWidth: true
        Layout.leftMargin: m3.space16
        Layout.rightMargin: m3.space16
        visible: text !== ''
        role: 'bodySmall'
        wrapMode: Text.Wrap
        lineHeightMode: Text.ProportionalHeight
        lineHeight: 1.0
        color: root.errorText !== '' ? m3.error : m3.surfaceVariantOn
        text: root.errorText !== '' ? root.errorText : root.supportingText
    }

    FontMetrics {
        id: fontMetrics
        font: password_tf.font
    }
}
