import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

Pane {
    id: openwalletdialog

    property string title: qsTr("Open Wallet")

    property string name
    property string path

    property bool _unlockClicked: false

    GridLayout {
        columns: 2
        width: parent.width

        Label {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            text: name
        }

        MessagePane {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            text: qsTr("Wallet requires password to unlock")
            visible: wallet_db.needsPassword
            width: parent.width * 2/3
            warning: true
        }

        MessagePane {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            text: qsTr("Invalid Password")
            visible: wallet_db.invalidPassword && _unlockClicked
            width: parent.width * 2/3
            error: true
        }

        Label {
            text: qsTr('Password')
            visible: wallet_db.needsPassword
        }

        TextField {
            id: password
            visible: wallet_db.needsPassword
            echoMode: TextInput.Password
        }

        Button {
            Layout.columnSpan: 2
            Layout.alignment: Qt.AlignHCenter
            visible: wallet_db.needsPassword
            text: qsTr("Unlock")
            onClicked: {
                _unlockClicked = true
                wallet_db.password = password.text
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
    }

    WalletDB {
        id: wallet_db
        path: openwalletdialog.path
        onSplitFinished: {
            // if wallet needed splitting, we close the pane and refresh the wallet list
            Daemon.availableWallets.reload()
            app.stack.pop()
        }
        onReadyChanged: {
            if (ready) {
                Daemon.load_wallet(openwalletdialog.path, password.text)
                app.stack.pop(null)
            }
        }
    }

}
