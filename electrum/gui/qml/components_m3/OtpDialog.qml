import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Two-factor code dialog of the Material 3 GUI (PaymentFlow, Daemon.currentWallet.onOtpRequested; M2-MAP F-2:
// an M3Dialog).
// repeats: components/OtpDialog.qml:8-89 @ e6df7e1c8 (the API: otpauth, open(); the field takes 6 digits as a
// password, any key clears the error; at 6 digits it waits and calls Daemon.currentWallet.submitOtp(<code>);
// onOtpSuccess -> otpauth = the code, accept(); onOtpFailed(code, message) -> the error message, the field is
// cleared; the busy indicator while waiting; the field is 6 characters wide and has the focus).
// Differences: Material 3 look: the neutral `verified_user` glyph (coordinator decision R-2) instead of the
// colored trustedcoin icon, an outlined field, the error in m3.error; a Cancel text button, which does what the
// Android back button does (doClose(), shown only when allowClose), disabled while the code is being submitted
// (the transaction goes on regardless, so it cannot promise a cancel); the width is that of M3Dialog (the factory
// no longer sets 2/3).
// Strings keep the translation context of the classic file (qsTranslate('OtpDialog', ...)).
M3Dialog {
    id: dialog

    title: qsTranslate('OtpDialog', 'Trustedcoin')
    iconSource: Qt.resolvedUrl('../../icons/m3/verified_user.png')

    property string otpauth

    property bool _waiting: false
    property string _otpError
    property string passwordCharacter: '8'
    focus: true

    contentItem: ColumnLayout {
        spacing: m3.space16

        M3Text {
            Layout.fillWidth: true
            role: 'bodyLarge'
            color: m3.surfaceVariantOn
            wrapMode: Text.Wrap
            horizontalAlignment: Text.AlignHCenter
            text: qsTranslate('OtpDialog', 'Enter Authenticator code')
        }

        TextField {
            id: otpEdit
            Layout.preferredWidth: leftPadding + rightPadding + fontMetrics.advanceWidth(passwordCharacter) * 6
                + m3.space16
            Layout.alignment: Qt.AlignHCenter
            Material.containerStyle: Material.Outlined
            Material.accent: dialog._otpError !== '' ? m3.error : m3.primary
            font.pixelSize: m3.textStyle('headlineSmall').size
            font.letterSpacing: 4
            color: m3.surfaceOn
            horizontalAlignment: TextInput.AlignHCenter
            maximumLength: 6
            inputMethodHints: Qt.ImhSensitiveData | Qt.ImhDigitsOnly
            echoMode: TextInput.Password
            focus: true
            enabled: !_waiting
            Keys.onPressed: _otpError = ''
            onTextChanged: {
                if (text.length == 6) {
                    _waiting = true
                    Daemon.currentWallet.submitOtp(otpEdit.text)
                }
            }
        }

        Item {
            Layout.fillWidth: true
            implicitHeight: Math.max(errorText.implicitHeight, 40)

            M3Text {
                id: errorText
                width: parent.width
                anchors.verticalCenter: parent.verticalCenter
                role: 'bodyMedium'
                color: m3.error
                wrapMode: Text.Wrap
                lineHeightMode: Text.ProportionalHeight
                lineHeight: 1.0
                horizontalAlignment: Text.AlignHCenter
                text: _otpError
            }

            BusyIndicator {
                anchors.centerIn: parent
                width: 40
                height: 40
                visible: _waiting
                running: _waiting
            }
        }
    }

    buttons: [
        M3Button {
            variant: 'text'
            text: qsTr('Cancel')
            visible: dialog.allowClose
            // once the code is submitted the server co-signs and the wallet broadcasts: nothing left to cancel
            enabled: !dialog._waiting
            onClicked: dialog.doClose()
        }
    ]

    Connections {
        target: Daemon.currentWallet
        function onOtpSuccess() {
            _waiting = false
            otpauth = otpEdit.text
            dialog.accept()
        }
        function onOtpFailed(code, message) {
            _waiting = false
            _otpError = message
            otpEdit.text = ''
        }
    }

    FontMetrics {
        id: fontMetrics
        font: otpEdit.font
    }
}
