import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
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

    implicitHeight: parent.height
    implicitWidth: parent.width

    title: qsTr('Sign/Verify Message')
    iconSource: Qt.resolvedUrl('../../icons/pen.png')

    padding: 0

    function validateAddress() {
        // TODO: not all types of addresses are valid (e.g. p2wsh)
        _addressValid = bitcoin.isAddress(addressField.text)
        _addressMine = Daemon.currentWallet.isAddressMine(addressField.text)
    }

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: constants.paddingLarge

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            Label {
                text: qsTr('Address')
                color: Material.accentColor
            }

            RowLayout {
                Layout.fillWidth: true
                TextField {
                    id: addressField
                    Layout.fillWidth: true
                    placeholderText: qsTr('Address')
                    font.family: FixedFont
                    onTextChanged: {
                        validateAddress()
                        _verified = SignVerifyMessageDialog.Check.Unknown
                    }
                }
                ToolButton {
                    icon.source: '../../icons/paste.png'
                    icon.color: 'transparent'
                    onClicked: {
                        addressField.text = AppController.clipboardToText()
                    }
                }
            }

            Label {
                text: qsTr('Message')
                color: Material.accentColor
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                ElTextArea {
                    id: plaintext
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    font.family: FixedFont
                    wrapMode: TextInput.Wrap
                    background: PaneInsetBackground {
                        baseColor: constants.darkerDialogBackground
                    }
                    onTextChanged: _verified = SignVerifyMessageDialog.Check.Unknown
                }
                ColumnLayout {
                    Layout.alignment: Qt.AlignTop
                    ToolButton {
                        icon.source: '../../icons/paste.png'
                        icon.color: 'transparent'
                        onClicked: {
                            plaintext.text = AppController.clipboardToText()
                        }
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: enabled ? 'transparent' : Material.iconDisabledColor
                        enabled: plaintext.text
                        onClicked: {
                            var dialog = app.genericShareDialog.createObject(app, {
                                title: qsTr('Message'),
                                text_qr: plaintext.text
                            })
                            dialog.open()
                        }
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Label {
                    text: qsTr('Signature')
                    color: Material.accentColor
                }
                Label {
                    Layout.alignment: Qt.AlignRight
                    visible: _verified != SignVerifyMessageDialog.Check.Unknown
                    text: _verified == SignVerifyMessageDialog.Check.Valid
                        ? qsTr('Valid!')
                        : qsTr('Invalid!')
                    color: _verified == SignVerifyMessageDialog.Check.Valid
                        ? constants.colorDone
                        : constants.colorError
                }
            }
            RowLayout {
                Layout.fillWidth: true
                ElTextArea {
                    id: signature
                    Layout.fillWidth: true
                    Layout.maximumHeight: fontMetrics.lineSpacing * 4 + topPadding + bottomPadding
                    Layout.minimumHeight: fontMetrics.lineSpacing * 4 + topPadding + bottomPadding
                    font.family: FixedFont
                    wrapMode: TextInput.Wrap
                    background: PaneInsetBackground {
                        baseColor: _verified == SignVerifyMessageDialog.Check.Unknown
                            ? constants.darkerDialogBackground
                            : _verified == SignVerifyMessageDialog.Check.Valid
                                ? constants.colorValidBackground
                                : constants.colorInvalidBackground
                    }
                    onTextChanged: _verified = SignVerifyMessageDialog.Check.Unknown
                }
                ColumnLayout {
                    Layout.alignment: Qt.AlignTop
                    ToolButton {
                        icon.source: '../../icons/paste.png'
                        icon.color: 'transparent'
                        onClicked: {
                            signature.text = AppController.clipboardToText()
                        }
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: enabled ? 'transparent' : Material.iconDisabledColor
                        enabled: signature.text
                        onClicked: {
                            var dialog = app.genericShareDialog.createObject(app, {
                                title: qsTr('Message signature'),
                                text_qr: signature.text
                            })
                            dialog.open()
                        }
                    }
                }
            }
        }

        ButtonContainer {
            Layout.fillWidth: true
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Sign')
                visible: Daemon.currentWallet.canSignMessage
                enabled: _addressMine
                icon.source: '../../icons/seal.png'
                onClicked: {
                    var sig = Daemon.currentWallet.signMessage(addressField.text, plaintext.text)
                    signature.text = sig
                }
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                enabled: _addressValid && signature.text
                text: qsTr('Verify')
                icon.source: '../../icons/confirmed.png'
                onClicked: {
                    var result = Daemon.verifyMessage(addressField.text, plaintext.text, signature.text)
                    _verified = result
                        ? SignVerifyMessageDialog.Check.Valid
                        : SignVerifyMessageDialog.Check.Invalid
                }
            }
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
