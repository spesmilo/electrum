import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import "../../../gui/qml/components/wizard"
import "../../../gui/qml/components/controls"

WizardComponent {
    valid: otpVerified

    property QtObject plugin

    property bool otpVerified: false

    ColumnLayout {
        width: parent.width

        Label {
            text: qsTr('Authenticator secret')
        }

        InfoTextArea {
            iconStyle: InfoTextArea.IconStyle.Error
            visible: plugin ? plugin.createRemoteKeyError : false
            text: plugin ? plugin.createRemoteKeyError : ''
        }

        QRImage {
            Layout.alignment: Qt.AlignHCenter
            qrdata: encodeURI('otpauth://totp/Electrum 2FA ' + wizard_data['wallet_name']
                    + '?secret=' + plugin.otpSecret + '&digits=6')
            render: plugin ? plugin.otpSecret : false
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
            Layout.preferredWidth: parent.width
            wrapMode: Text.Wrap
            text: qsTr('Enter or scan into authenticator app. Then authenticate below')
            visible: plugin.otpSecret && !otpVerified
        }

        TextField {
            id: otp_auth
            Layout.alignment: Qt.AlignHCenter
            focus: true
            visible: plugin.otpSecret && !otpVerified
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

        Image {
            Layout.alignment: Qt.AlignHCenter
            source: '../../../gui/icons/confirmed.png'
            visible: otpVerified
            Layout.preferredWidth: constants.iconSizeLarge
            Layout.preferredHeight: constants.iconSizeLarge
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
        function onOtpError() {
            console.log('OTP verify error')
            // TODO: show error in UI
        }
        function onOtpSuccess() {
            console.log('OTP verify success')
            otpVerified = true
        }
    }
}

