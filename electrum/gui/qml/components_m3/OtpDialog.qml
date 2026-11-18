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
// no longer sets 2/3); the content scrolls when the keyboard leaves too little height (the height formula of
// PasswordDialog.qml), and what matters is scrolled into view: the code field with the focus, or, while the code
// is being submitted and after a refusal until a digit is typed again, the row of the busy indicator and the error.
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

    // the dialog never grows past the free zone (keyboard included): the content scrolls instead
    // (as PasswordDialog.qml: centered, the same margin above and below, clear of the status bar and of the
    // navigation bar; while the keyboard is open the navigation bar is under it and the margin is smaller)
    height: Math.min(implicitHeight, parent
        ? parent.height - 2 * (app.keyboardFreeZone.state != 'visible'
            ? m3.space24 + Math.max(app.statusBarHeight, app.navigationBarHeight)
            : m3.space8 + app.statusBarHeight)
        : implicitHeight)

    contentItem: Flickable {
        id: flick
        implicitHeight: form.implicitHeight
        contentHeight: form.implicitHeight
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        // the keyboard shrinks the dialog after the field got the focus, a long error grows the content (laid out
        // after the error was set): keep in view what matters now
        onHeightChanged: dialog._keepInView()
        onContentHeightChanged: dialog._keepInView()

        ScrollIndicator.vertical: ScrollIndicator { }

        ColumnLayout {
            id: form
            width: flick.width
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
                id: feedback
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

    // what a shrunk dialog shows: the row under the field (the busy indicator, the error) while the code is being
    // submitted and after a refusal until a digit is typed again, otherwise the code field
    readonly property bool _feedbackInView: _waiting || (_otpError !== '' && otpEdit.text === '')
    on_FeedbackInViewChanged: _keepInView()

    // the row whole, its bottom at the bottom of the content window (its top, if it is taller), else the field
    function _keepInView() {
        if (!_feedbackInView) {
            _showCodeField()
            return
        }
        if (flick.height <= 0)
            return
        flick.contentY = Math.max(0, Math.min(feedback.y, feedback.y + feedback.implicitHeight - flick.height,
            flick.contentHeight - flick.height))
    }

    // scroll the content so that the code field is seen whole while it has the focus (Flickable does not follow
    // the focus)
    function _showCodeField() {
        if (!otpEdit.activeFocus || flick.height <= 0)
            return
        var top = otpEdit.mapToItem(form, 0, 0).y
        var bottom = top + otpEdit.height
        if (top < flick.contentY)
            flick.contentY = top
        else if (bottom > flick.contentY + flick.height)
            flick.contentY = Math.min(bottom - flick.height, Math.max(0, flick.contentHeight - flick.height))
    }

    Connections {
        target: otpEdit
        function onActiveFocusChanged() { dialog._keepInView() }
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
