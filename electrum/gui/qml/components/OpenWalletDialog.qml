import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: openwalletdialog

    property string name
    property string path

    property bool _invalidPassword: false
    property bool _unlockClicked: false

    title: qsTr('Open Wallet')
    iconSource: Qt.resolvedUrl('../../icons/wallet.png')

    focus: true

    width: parent.width * 4/5
    anchors.centerIn: parent

    padding: 0

    ColumnLayout {
        spacing: 0
        width: parent.width

        ColumnLayout {
            id: rootLayout
            Layout.fillWidth: true
            Layout.leftMargin: constants.paddingXXLarge
            Layout.rightMargin: constants.paddingXXLarge
            spacing: constants.paddingLarge

            InfoTextArea {
                id: notice
                text: Daemon.singlePasswordEnabled || !Daemon.currentWallet
                    ? qsTr('Please enter password')
                    : qsTr('Wallet <b>%1</b> requires password to unlock').arg(name)
                iconStyle: InfoTextArea.IconStyle.Warn
                Layout.fillWidth: true
            }

            Label {
                text: qsTr('Password')
                Layout.fillWidth: true
                color: Material.accentColor
            }

            PasswordField {
                id: password
                Layout.fillWidth: true
                Layout.leftMargin: constants.paddingXLarge

                onTextChanged: {
                    unlockButton.enabled = true
                    _unlockClicked = false
                    _invalidPassword = false
                }
                onAccepted: {
                    unlock()
                }
            }

            Label {
                Layout.alignment: Qt.AlignHCenter
                text: _invalidPassword && _unlockClicked ? qsTr("Invalid Password") : ''
                color: constants.colorError
                font.pixelSize: constants.fontSizeLarge
            }
        }

        FlatButton {
            id: unlockButton
            Layout.fillWidth: true
            icon.source: '../../icons/unlock.png'
            text: qsTr("Unlock")
            onClicked: {
                unlock()
            }
        }

    }

    function unlock() {
        unlockButton.enabled = false
        _unlockClicked = true
        Daemon.loadWallet(openwalletdialog.path, password.text)
    }

    Connections {
        target: Daemon
        function onWalletRequiresPassword() {
            console.log('invalid password')
            _invalidPassword = true
            password.tf.forceActiveFocus()
        }
        function onWalletLoaded() {
            openwalletdialog.close()
        }
    }

    Component.onCompleted: {
        password.tf.forceActiveFocus()
    }
}
