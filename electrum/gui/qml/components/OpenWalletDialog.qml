import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: openwalletdialog

    width: parent.width
    height: parent.height

    title: qsTr("Open Wallet")
    iconSource: '../../../icons/wallet.png'

    property string name
    property string path

    standardButtons: Dialog.Cancel

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    focus: true

    property bool _unlockClicked: false

    ColumnLayout {
        width: parent.width
        spacing: constants.paddingLarge

        Label {
            Layout.alignment: Qt.AlignHCenter
            text: name
        }

        Item {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: passwordLayout.width
            Layout.preferredHeight: notice.height
            InfoTextArea {
                id: notice
                text: qsTr("Wallet requires password to unlock")
                visible: wallet_db.needsPassword
                iconStyle: InfoTextArea.IconStyle.Warn
                width: parent.width
            }
        }

        RowLayout {
            id: passwordLayout
            Layout.alignment: Qt.AlignHCenter
            Layout.maximumWidth: parent.width * 2/3
            Label {
                text: qsTr('Password')
                visible: wallet_db.needsPassword
                Layout.fillWidth: true
            }

            PasswordField {
                id: password
                visible: wallet_db.needsPassword
                Layout.fillWidth: true
                onTextChanged: {
                    unlockButton.enabled = true
                    _unlockClicked = false
                }
                onAccepted: {
                    unlock()
                }
            }
        }

        Label {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            text: !wallet_db.validPassword && _unlockClicked ? qsTr("Invalid Password") : ''
            color: constants.colorError
            font.pixelSize: constants.fontSizeLarge
        }

        Button {
            id: unlockButton
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            visible: wallet_db.needsPassword
            text: qsTr("Unlock")
            onClicked: {
                unlock()
            }
        }

        Label {
            text: qsTr('Select HW device')
            visible: wallet_db.needsHWDevice
        }

        ComboBox {
            id: hw_device
            model: ['','Not implemented']
            visible: wallet_db.needsHWDevice
        }

        Label {
            text: qsTr('Wallet requires splitting')
            visible: wallet_db.requiresSplit
        }

        Button {
            visible: wallet_db.requiresSplit
            text: qsTr('Split wallet')
            onClicked: wallet_db.doSplit()
        }

        BusyIndicator {
            id: busy
            running: false
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
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
                busy.running = true
                Daemon.load_wallet(openwalletdialog.path, password.text)
                openwalletdialog.close()
            }
        }
        onInvalidPassword: {
            password.tf.forceActiveFocus()
        }
    }

    Component.onCompleted: {
        wallet_db.verify()
    }
}
