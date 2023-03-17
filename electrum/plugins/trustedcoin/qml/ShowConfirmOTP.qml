import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    valid: otpVerified

    property QtObject plugin

    property bool otpVerified: false

    function apply() {
        wizard_data['trustedcoin_new_otp_secret'] = requestNewSecret.checked
    }

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Authenticator secret')
        }

        InfoTextArea {
            id: errorBox
            Layout.fillWidth: true
            iconStyle: InfoTextArea.IconStyle.Error
            visible: !otpVerified && plugin.remoteKeyState == 'error'
        }

        InfoTextArea {
            Layout.fillWidth: true
            iconStyle: InfoTextArea.IconStyle.Warn
            visible: plugin.remoteKeyState == 'wallet_known'
            text: qsTr('This wallet is already registered with TrustedCoin. ')
                + qsTr('To finalize wallet creation, please enter your Google Authenticator Code. ')
        }

        QRImage {
            Layout.alignment: Qt.AlignHCenter
            visible: plugin.remoteKeyState == ''
            qrdata: encodeURI('otpauth://totp/Electrum 2FA ' + wizard_data['wallet_name']
                    + '?secret=' + plugin.otpSecret + '&digits=6')
            render: plugin.otpSecret
        }

        TextHighlightPane {
            Layout.alignment: Qt.AlignHCenter
            visible: plugin.otpSecret
            Label {
                text: plugin.otpSecret
                font.family: FixedFont
                font.bold: true
            }
        }

        Label {
            Layout.fillWidth: true
            visible: !otpVerified && plugin.otpSecret
            wrapMode: Text.Wrap
            text: qsTr('Enter or scan into authenticator app. Then authenticate below')
        }

        Label {
            Layout.fillWidth: true
            visible: !otpVerified && plugin.remoteKeyState == 'wallet_known'
            wrapMode: Text.Wrap
            text: qsTr('If you still have your OTP secret, then authenticate below')
        }

        TextField {
            id: otp_auth
            visible: !otpVerified && (plugin.otpSecret || plugin.remoteKeyState == 'wallet_known')
            Layout.alignment: Qt.AlignHCenter
            focus: true
            inputMethodHints: Qt.ImhSensitiveData | Qt.ImhDigitsOnly
            font.family: FixedFont
            font.pixelSize: constants.fontSizeLarge
            onTextChanged: {
                if (text.length >= 6) {
                    plugin.checkOtp(plugin.shortId, otp_auth.text)
                    text = ''
                }
            }
        }

        Label {
            Layout.fillWidth: true
            visible: !otpVerified && plugin.remoteKeyState == 'wallet_known'
            wrapMode: Text.Wrap
            text: qsTr('Otherwise, you can request your OTP secret from the server, by pressing the button below')
        }

        Button {
            Layout.alignment: Qt.AlignHCenter
            visible: plugin.remoteKeyState == 'wallet_known' && !otpVerified
            text: qsTr('Request OTP secret')
            onClicked: plugin.resetOtpSecret()
        }

        Image {
            Layout.alignment: Qt.AlignHCenter
            source: '../../../gui/icons/confirmed.png'
            visible: otpVerified
            Layout.preferredWidth: constants.iconSizeXLarge
            Layout.preferredHeight: constants.iconSizeXLarge
        }
    }

    BusyIndicator {
        anchors.centerIn: parent
        visible: plugin ? plugin.busy : false
        running: visible
    }

    Component.onCompleted: {
        plugin = AppController.plugin('trustedcoin')
        plugin.createKeystore(wizard_data['2fa_email'])
        otp_auth.forceActiveFocus()
    }

    Connections {
        target: plugin
        function onOtpError(message) {
            console.log('OTP verify error')
            errorBox.text = message
        }
        function onOtpSuccess() {
            console.log('OTP verify success')
            otpVerified = true
        }
        function onRemoteKeyError(message) {
            errorBox.text = message
        }
    }
}

