import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.14
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr('Trustedcoin')
    iconSource: '../../../icons/trustedcoin-status.png'

    property string otpauth

    property bool _waiting: false
    property string _otpError

    standardButtons: Dialog.Cancel

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

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
            onTextChanged: {
                if (activeFocus)
                    _otpError = ''
            }
        }

        Label {
            opacity: _otpError ? 1 : 0
            text: _otpError
            color: constants.colorError
            Layout.alignment: Qt.AlignHCenter
        }

        Button {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            text: qsTr('Submit')
            enabled: !_waiting
            onClicked: {
                _waiting = true
                Daemon.currentWallet.submitOtp(otpEdit.text)
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
