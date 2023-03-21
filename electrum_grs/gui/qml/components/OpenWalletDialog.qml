import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: openwalletdialog

    property string name
    property string path

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
                text: Daemon.singlePasswordEnabled
                    ? qsTr('Please enter password')
                    : qsTr('Wallet <b>%1</b> requires password to unlock').arg(name)
                visible: wallet_db.needsPassword
                iconStyle: InfoTextArea.IconStyle.Warn
                Layout.fillWidth: true
            }

            Label {
                text: qsTr('Password')
                visible: wallet_db.needsPassword
                Layout.fillWidth: true
                color: Material.accentColor
            }

            PasswordField {
                id: password
                Layout.fillWidth: true
                Layout.leftMargin: constants.paddingXLarge
                visible: wallet_db.needsPassword

                onTextChanged: {
                    unlockButton.enabled = true
                    _unlockClicked = false
                }
                onAccepted: {
                    unlock()
                }
            }

            Label {
                Layout.alignment: Qt.AlignHCenter
                text: !wallet_db.validPassword && _unlockClicked ? qsTr("Invalid Password") : ''
                color: constants.colorError
                font.pixelSize: constants.fontSizeLarge
            }

            Label {
                Layout.alignment: Qt.AlignHCenter
                visible: wallet_db.requiresSplit
                text: qsTr('Wallet requires splitting')
                font.pixelSize: constants.fontSizeLarge
            }

            FlatButton {
                Layout.alignment: Qt.AlignHCenter
                visible: wallet_db.requiresSplit
                text: qsTr('Split wallet')
                onClicked: wallet_db.doSplit()
            }
        }

        FlatButton {
            id: unlockButton
            Layout.fillWidth: true
            visible: wallet_db.needsPassword
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
        wallet_db.password = password.text
        wallet_db.verify()
    }

    WalletDB {
        id: wallet_db
        path: openwalletdialog.path
        onSplitFinished: {
            // if wallet needed splitting, we close the pane and refresh the wallet list
            Daemon.availableWallets.reload()
            openwalletdialog.close()
        }
        onReadyChanged: {
            if (ready) {
                Daemon.load_wallet(openwalletdialog.path, password.text)
                openwalletdialog.close()
            }
        }
        onInvalidPassword: {
            password.tf.forceActiveFocus()
        }
        onNeedsPasswordChanged: {
            notice.visible = needsPassword
        }
        onWalletOpenProblem: {
            openwalletdialog.close()
            Daemon.onWalletOpenProblem(error)
        }
    }

    Component.onCompleted: {
        wallet_db.verify()
    }
}
