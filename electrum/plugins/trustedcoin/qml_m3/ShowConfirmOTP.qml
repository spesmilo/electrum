import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../../../gui/qml/components_m3/wizard"
import "../../../gui/qml/components_m3/controls"

// Material 3 page of the trustedcoin (2FA) wizard: the authenticator secret (QR and text) and the confirmation with a
// one-time password. Loaded only by the Material 3 wizard (table _m3PluginPages of components_m3/wizard/Wizard.qml).
// repeats: plugins/trustedcoin/qml/ShowConfirmOTP.qml:8-164 @ e6df7e1c8 (valid = otpVerified; the error box and the
// "already registered" notice with their conditions; the QR of the otpauth URI (qrdata verbatim) while the remote key
// is new or reset, a tap copies the secret ("Copied!"), the commented-out openUrlExternally kept as a comment; the
// secret, a tap copies it; the three hints with their conditions; the OTP field (digits only, 0...999999, six digits
// -> plugin.checkOtp(plugin.shortId, otp) and the field cleared); "Request OTP secret" -> resetOtpSecret(); the
// verified mark; the spinner while plugin.busy; on completion: plugin, createKeystore(), the focus in the OTP field;
// otpError / remoteKeyError -> the error box, otpSuccess -> otpVerified).
// Look (DESIGN-M2-onboarding.md 4): the heading, the notices as M3InfoText (error, warn), the QR as M3QRImage (black
// on white in both themes), the secret in the fixed font, bold, on an M3Card, the hints as bodyMedium, the OTP as a
// centered M3TextField in the fixed font 22, the request as a tonal M3Button, the verified mark as the check_circle
// glyph 48 dp in m3.success (classic: confirmed.png), "Copied!" by M3Toaster. The page scrolls and keeps the OTP field
// visible above the keyboard.
// Strings carried over keep the translation context of ShowConfirmOTP.qml.
WizardComponent {
    id: root
    valid: otpVerified

    property QtObject plugin

    property bool otpVerified: false

    Flickable {
        id: flick
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        onHeightChanged: {
            if (otp_auth.activeFocus)
                root.ensureVisible(flick, otpField)
        }

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('ShowConfirmOTP', 'Authenticator secret')
            }

            M3InfoText {
                id: errorBox
                Layout.fillWidth: true
                compact: true
                iconStyle: M3InfoText.IconStyle.Error
                visible: !otpVerified && plugin.remoteKeyState == 'error'
            }

            M3InfoText {
                Layout.fillWidth: true
                compact: true
                iconStyle: M3InfoText.IconStyle.Warn
                visible: plugin.remoteKeyState == 'wallet_known'
                text: qsTranslate('ShowConfirmOTP', 'This wallet is already registered with TrustedCoin. ')
                    + qsTranslate('ShowConfirmOTP', 'To finalize wallet creation, please enter your Google Authenticator Code. ')
            }

            M3QRImage {
                Layout.alignment: Qt.AlignHCenter
                visible: plugin.remoteKeyState == 'new' || plugin.remoteKeyState == 'reset'
                qrdata: encodeURI('otpauth://totp/Electrum 2FA ' + wizard_data['wallet_name']
                        + '?secret=' + plugin.otpSecret + '&digits=6')
                render: plugin.otpSecret
                onClicked: {
                    if (plugin.otpSecret) {
                        AppController.textToClipboard(plugin.otpSecret)
                        toaster.show(this, qsTranslate('ShowConfirmOTP', 'Copied!'))
                        // On Android the app will get killed when switching to the authenticator app,
                        // losing the wizard state. TODO: re-enable once we have means to keep app alive in background.
                        // if (AppController.isAndroid()) {
                        //     Qt.openUrlExternally(qrdata)
                        // } else {
                        //     AppController.textToClipboard(plugin.otpSecret)
                        //     toaster.show(this, qsTranslate('ShowConfirmOTP', 'Copied!'))
                        // }
                    }
                }
            }

            M3Card {
                id: otpSecretPane
                Layout.alignment: Qt.AlignHCenter
                Layout.maximumWidth: mainLayout.width
                visible: plugin.otpSecret
                clickable: true
                padding: m3.space12
                leftPadding: m3.space16
                rightPadding: m3.space16
                onClicked: {
                    AppController.textToClipboard(plugin.otpSecret)
                    toaster.show(otpSecretPane, qsTranslate('ShowConfirmOTP', 'Copied!'))
                }

                M3Text {
                    width: Math.min(implicitWidth, mainLayout.width - otpSecretPane.leftPadding - otpSecretPane.rightPadding)
                    role: 'bodyLarge'
                    font.family: FixedFont
                    font.bold: true
                    wrapMode: Text.WrapAnywhere
                    text: plugin.otpSecret
                }
            }

            M3Text {
                Layout.fillWidth: true
                visible: !otpVerified && plugin.otpSecret
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                text: qsTranslate('ShowConfirmOTP', 'Enter or scan into authenticator app. Then authenticate below')
            }

            M3Text {
                Layout.fillWidth: true
                visible: !otpVerified && plugin.remoteKeyState == 'wallet_known'
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                text: qsTranslate('ShowConfirmOTP', 'If you still have your OTP secret, then authenticate below')
            }

            M3TextField {
                id: otpField
                visible: !otpVerified && (plugin.otpSecret || plugin.remoteKeyState == 'wallet_known')
                Layout.alignment: Qt.AlignHCenter
                Layout.preferredWidth: Math.min(240, mainLayout.width)
                focus: true
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhDigitsOnly
                validator: IntValidator {bottom: 0; top: 999999;}
                field.font.family: FixedFont
                field.font.pixelSize: 22
                field.horizontalAlignment: TextInput.AlignHCenter
                onTextChanged: {
                    if (text.length >= 6) {
                        plugin.checkOtp(plugin.shortId, otp_auth.text)
                        text = ''
                    }
                }
            }

            M3Text {
                Layout.fillWidth: true
                visible: !otpVerified && plugin.remoteKeyState == 'wallet_known'
                role: 'bodyMedium'
                color: m3.surfaceVariantOn
                wrapMode: Text.Wrap
                text: qsTranslate('ShowConfirmOTP', 'Otherwise, you can request your OTP secret from the server, by pressing the button below')
            }

            M3Button {
                Layout.alignment: Qt.AlignHCenter
                visible: plugin.remoteKeyState == 'wallet_known' && !otpVerified
                variant: 'tonal'
                text: qsTranslate('ShowConfirmOTP', 'Request OTP secret')
                onClicked: plugin.resetOtpSecret()
            }

            M3Icon {
                Layout.alignment: Qt.AlignHCenter
                visible: otpVerified
                size: 48
                color: m3.success
                source: Qt.resolvedUrl('../../../gui/icons/m3/check_circle.png')
            }
        }
    }

    // the TextField of the classic page
    property alias otp_auth: otpField.field

    Connections {
        target: otpField.field
        function onActiveFocusChanged() {
            if (otpField.field.activeFocus)
                Qt.callLater(root.ensureVisible, flick, otpField)
        }
    }

    BusyIndicator {
        anchors.centerIn: parent
        visible: plugin ? plugin.busy : false
        running: visible
    }

    Component.onCompleted: {
        plugin = AppController.plugin('trustedcoin')
        plugin.createKeystore()
        otp_auth.forceActiveFocus()
    }

    M3Toaster {
        id: toaster
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
