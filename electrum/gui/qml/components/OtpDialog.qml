import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('Trustedcoin')
    iconSource: '../../../icons/trustedcoin-status.png'

    property string otpauth

    property bool _waiting: false
    property string _otpError

    focus: true

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Enter Authenticator code')
            font.pixelSize: constants.fontSizeLarge
            Layout.alignment: Qt.AlignHCenter
        }

        TextField {
            id: otpEdit
            Layout.preferredWidth: fontMetrics.advanceWidth(passwordCharacter) * 6
            Layout.alignment: Qt.AlignHCenter
            font.pixelSize: constants.fontSizeXXLarge
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

        Label {
            Layout.topMargin: constants.paddingMedium
            Layout.bottomMargin: constants.paddingMedium
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            wrapMode: Text.Wrap

            text: _otpError
            color: constants.colorError

            BusyIndicator {
                anchors.centerIn: parent
                width: constants.iconSizeXLarge
                height: constants.iconSizeXLarge
                visible: _waiting
                running: _waiting
            }
        }
    }

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
