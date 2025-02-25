import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

ElDialog {
    id: dialog

    title: qsTr("Enter wallet name")
    iconSource: Qt.resolvedUrl('../../icons/pen.png')

    property string infotext

    property bool _valid: false

    anchors.centerIn: parent
    width: parent.width * 4/5
    padding: 0

    ColumnLayout {
        id: rootLayout
        width: parent.width
        spacing: 0

        ColumnLayout {
            Layout.leftMargin: constants.paddingXXLarge
            Layout.rightMargin: constants.paddingXXLarge

            InfoTextArea {
                visible: infotext
                text: infotext
                Layout.bottomMargin: constants.paddingMedium
                Layout.fillWidth: true
            }

            Label {
                Layout.fillWidth: true
                text: qsTr('Wallet name')
                color: Material.accentColor
            }

            TextField {
                id: wallet_name
                Layout.fillWidth: true
                Layout.leftMargin: constants.paddingXLarge
                Layout.rightMargin: constants.paddingXLarge
                onTextChanged: {
                    var name = text.trim()
                    if (!text || text == Daemon.currentWallet.name) {
                        _valid = false
                        infotext = ''
                    } else {
                        _valid = Daemon.isValidNewWalletName(name)
                        if (_valid)
                            infotext = ''
                        else
                            infotext = qsTr('Invalid name')
                    }
                }
            }
        }

        FlatButton {
            Layout.fillWidth: true
            text: qsTr("Ok")
            icon.source: '../../icons/confirmed.png'
            enabled: _valid
            onClicked: {
                var name = wallet_name.text.trim()
                if (Daemon.isValidNewWalletName(name)) {
                    console.log('renaming.. ' + name)
                    var result = Daemon.renameWallet(Daemon.currentWallet, name)
                    if (result)
                        dialog.close()
                }
            }
        }
    }

    Component.onCompleted: {
        wallet_name.text = Daemon.currentWallet.name
    }
}
