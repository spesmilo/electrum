import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Sign/Verify Message of the Material 3 GUI (factory app.signVerifyMessageDialog in main.qml: from the overflow menu
// of the wallet and from the address details, with `address`). A full-screen dialog.
// repeats: components/SignVerifyMessageDialog.qml:10-253: the API (`address`, open(); the result of a
// check in the enum Check), the address check (Bitcoin.isAddress, Daemon.currentWallet.isAddressMine), address,
// message and signature with their paste buttons (AppController.clipboardToText) and the share dialogs of the
// message and the signature (app.genericShareDialog with text_qr), the check result reset on every edit, Sign (when
// the wallet can sign, enabled for an address of this wallet; the wallet answers with messageSigned) and Verify
// (enabled for a valid address and a signature; Daemon.verifyMessage), the error handlers of the wallet and the
// daemon, the address set on completion. Only the look differs: the check result colors the signature box
// (successContainer / errorContainer) and its label (success / error).
// Strings keep the translation context of the classic file (qsTranslate('SignVerifyMessageDialog', ...)).
M3FullScreenDialog {
    id: dialog

    enum Check {
        Unknown,
        Valid,
        Invalid
    }

    property string address

    property bool _addressValid: false
    property bool _addressMine: false
    property int _verified: SignVerifyMessageDialog.Check.Unknown

    title: qsTranslate('SignVerifyMessageDialog', 'Sign/Verify Message')

    function validateAddress() {
        // TODO: not all types of addresses are valid (e.g. p2wsh)
        _addressValid = bitcoin.isAddress(addressField.text)
        _addressMine = Daemon.currentWallet.isAddressMine(addressField.text)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(dialog.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space8

                // --- address (SignVerifyMessageDialog.qml:50-74) ---
                RowLayout {
                    Layout.fillWidth: true
                    spacing: m3.space4

                    M3TextField {
                        id: addressField
                        Layout.fillWidth: true
                        label: qsTranslate('SignVerifyMessageDialog', 'Address')
                        field.font.family: FixedFont
                        onTextChanged: {
                            validateAddress()
                            _verified = SignVerifyMessageDialog.Check.Unknown
                        }
                    }
                    M3IconButton {
                        Layout.alignment: Qt.AlignTop
                        tooltip: qsTr('Paste')
                        icon.source: Qt.resolvedUrl('../../icons/m3/content_paste.png')
                        onClicked: {
                            addressField.text = AppController.clipboardToText()
                        }
                    }
                }

                // --- message (SignVerifyMessageDialog.qml:76-117) ---
                M3Text {
                    Layout.topMargin: m3.space8
                    role: 'titleSmall'
                    color: m3.primary
                    text: qsTranslate('SignVerifyMessageDialog', 'Message')
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: m3.space4

                    M3TextArea {
                        id: plaintext
                        Layout.fillWidth: true
                        Layout.preferredHeight: Math.max(120, fontMetrics.lineSpacing * 6 + 2 * m3.space8)
                        font.family: FixedFont
                        wrapMode: TextInput.Wrap
                        onTextChanged: _verified = SignVerifyMessageDialog.Check.Unknown
                    }
                    ColumnLayout {
                        Layout.alignment: Qt.AlignTop
                        spacing: 0
                        M3IconButton {
                            tooltip: qsTr('Paste')
                            icon.source: Qt.resolvedUrl('../../icons/m3/content_paste.png')
                            onClicked: {
                                plaintext.text = AppController.clipboardToText()
                            }
                        }
                        M3IconButton {
                            tooltip: qsTr('Share')
                            icon.source: Qt.resolvedUrl('../../icons/m3/share.png')
                            enabled: plaintext.text
                            opacity: enabled ? 1 : m3.disabledContentOpacity
                            onClicked: {
                                var dialog = app.genericShareDialog.createObject(app, {
                                    title: qsTranslate('SignVerifyMessageDialog', 'Message'),
                                    text_qr: plaintext.text
                                })
                                dialog.open()
                            }
                        }
                    }
                }

                // --- signature (SignVerifyMessageDialog.qml:119-179) ---
                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: m3.space8
                    M3Text {
                        Layout.fillWidth: true
                        role: 'titleSmall'
                        color: m3.primary
                        text: qsTranslate('SignVerifyMessageDialog', 'Signature')
                    }
                    M3Text {
                        Layout.alignment: Qt.AlignRight
                        visible: _verified != SignVerifyMessageDialog.Check.Unknown
                        role: 'labelLarge'
                        text: _verified == SignVerifyMessageDialog.Check.Valid
                            ? qsTranslate('SignVerifyMessageDialog', 'Valid!')
                            : qsTranslate('SignVerifyMessageDialog', 'Invalid!')
                        color: _verified == SignVerifyMessageDialog.Check.Valid
                            ? m3.success
                            : m3.error
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    spacing: m3.space4

                    M3TextArea {
                        id: signature
                        Layout.fillWidth: true
                        Layout.maximumHeight: fontMetrics.lineSpacing * 4 + topPadding + m3.space4 + m3.space8
                        Layout.minimumHeight: fontMetrics.lineSpacing * 4 + topPadding + m3.space4 + m3.space8
                        font.family: FixedFont
                        wrapMode: TextInput.Wrap
                        inputMethodHints: Qt.ImhNoPredictiveText
                        errorText: _verified == SignVerifyMessageDialog.Check.Invalid ? ' ' : ''

                        background: Rectangle {
                            radius: m3.radiusXS
                            color: _verified == SignVerifyMessageDialog.Check.Unknown
                                ? 'transparent'
                                : _verified == SignVerifyMessageDialog.Check.Valid
                                    ? m3.successContainer
                                    : m3.errorContainer
                        }
                        onTextChanged: _verified = SignVerifyMessageDialog.Check.Unknown
                    }
                    ColumnLayout {
                        Layout.alignment: Qt.AlignTop
                        spacing: 0
                        M3IconButton {
                            tooltip: qsTr('Paste')
                            icon.source: Qt.resolvedUrl('../../icons/m3/content_paste.png')
                            onClicked: {
                                signature.text = AppController.clipboardToText()
                            }
                        }
                        M3IconButton {
                            tooltip: qsTr('Share')
                            icon.source: Qt.resolvedUrl('../../icons/m3/share.png')
                            enabled: signature.text
                            opacity: enabled ? 1 : m3.disabledContentOpacity
                            onClicked: {
                                var dialog = app.genericShareDialog.createObject(app, {
                                    title: qsTranslate('SignVerifyMessageDialog', 'Message signature'),
                                    text_qr: signature.text
                                })
                                dialog.open()
                            }
                        }
                    }
                }
            }
        }

        // --- Sign and Verify (SignVerifyMessageDialog.qml:182-210): below the content ---
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: buttons.implicitHeight + 2 * m3.space16
            color: m3.surface

            RowLayout {
                id: buttons
                readonly property int margin: m3.screenMargin(dialog.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                spacing: m3.space8

                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'filled'
                    size: 56
                    text: qsTranslate('SignVerifyMessageDialog', 'Sign')
                    visible: Daemon.currentWallet.canSignMessage
                    enabled: _addressMine
                    icon.source: Qt.resolvedUrl('../../icons/m3/draw.png')
                    onClicked: {
                        Daemon.currentWallet.signMessage(addressField.text, plaintext.text)
                        // emits messageSigned(sig)
                    }
                }
                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: Daemon.currentWallet.canSignMessage ? 'tonal' : 'filled'
                    size: 56
                    enabled: _addressValid && signature.text
                    text: qsTranslate('SignVerifyMessageDialog', 'Verify')
                    icon.source: Qt.resolvedUrl('../../icons/m3/verified_user.png')
                    onClicked: {
                        var result = Daemon.verifyMessage(addressField.text, plaintext.text, signature.text)
                        _verified = result
                            ? SignVerifyMessageDialog.Check.Valid
                            : SignVerifyMessageDialog.Check.Invalid
                    }
                }
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onMessageSigned(sig) {
            signature.text = sig
        }
        function onSignMessageError(error) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('SignVerifyMessageDialog', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                text: error
            })
            dialog.open()
        }
    }

    Connections {
        target: Daemon
        function onVerifyMessageError(error) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('SignVerifyMessageDialog', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                text: error
            })
            dialog.open()
        }
    }

    Component.onCompleted: {
        addressField.text = address
    }

    Bitcoin {
        id: bitcoin
    }

    FontMetrics {
        id: fontMetrics
        font: signature.font
    }
}
