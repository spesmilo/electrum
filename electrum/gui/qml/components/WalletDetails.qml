import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem
    objectName: 'WalletDetails'

    padding: 0

    property bool _is2fa: Daemon.currentWallet && Daemon.currentWallet.walletType == '2fa'

    function enableLightning() {
        var dialog = app.messageDialog.createObject(rootItem, {
            title: qsTr('Enable Lightning for this wallet?'),
            yesno: true
        })
        dialog.accepted.connect(function() {
            Daemon.currentWallet.enableLightning()
        })
        dialog.open()
    }

    function importAddressesKeys() {
        var dialog = importAddressesKeysDialog.createObject(rootItem)
        dialog.open()
    }

    ColumnLayout {
        id: rootLayout
        anchors.fill: parent
        spacing: 0

        Flickable {
            Layout.fillWidth: true
            Layout.fillHeight: true

            contentHeight: flickableRoot.height
            clip: true
            interactive: height < contentHeight

            Pane {
                id: flickableRoot
                width: parent.width
                padding: constants.paddingLarge

                ColumnLayout {
                    width: parent.width
                    spacing: constants.paddingLarge

                    Heading {
                        text: qsTr('Wallet details')
                    }

                    GridLayout {
                        columns: 3
                        Layout.alignment: Qt.AlignHCenter

                        Tag {
                            Layout.alignment: Qt.AlignHCenter
                            text: Daemon.currentWallet.walletType
                            font.pixelSize: constants.fontSizeSmall
                            font.bold: true
                            iconSource: '../../../icons/wallet.png'
                        }
                        Tag {
                            Layout.alignment: Qt.AlignHCenter
                            text: Daemon.currentWallet.txinType
                            font.pixelSize: constants.fontSizeSmall
                            font.bold: true
                            iconSource: '../../../icons/script_white.png'
                        }
                        Tag {
                            Layout.alignment: Qt.AlignHCenter
                            text: qsTr('HD')
                            visible: Daemon.currentWallet.isDeterministic
                            font.pixelSize: constants.fontSizeSmall
                            font.bold: true
                            iconSource: '../../../icons/hd_white.png'
                        }
                        Tag {
                            Layout.alignment: Qt.AlignHCenter
                            text: qsTr('Watch only')
                            visible: Daemon.currentWallet.isWatchOnly
                            font.pixelSize: constants.fontSizeSmall
                            font.bold: true
                            iconSource: '../../../icons/eye1.png'
                        }
                        Tag {
                            Layout.alignment: Qt.AlignHCenter
                            text: qsTr('Encrypted')
                            visible: Daemon.currentWallet.isEncrypted
                            font.pixelSize: constants.fontSizeSmall
                            font.bold: true
                            iconSource: '../../../icons/key.png'
                        }
                        Tag {
                            Layout.alignment: Qt.AlignHCenter
                            text: qsTr('HW')
                            visible: Daemon.currentWallet.isHardware
                            font.pixelSize: constants.fontSizeSmall
                            font.bold: true
                            iconSource: '../../../icons/seed.png'
                        }
                        Tag {
                            Layout.alignment: Qt.AlignHCenter
                            text: qsTr('Lightning')
                            visible: Daemon.currentWallet.isLightning
                            font.pixelSize: constants.fontSizeSmall
                            font.bold: true
                            iconSource: '../../../icons/lightning.png'
                        }
                        Tag {
                            Layout.alignment: Qt.AlignHCenter
                            text: qsTr('Seed')
                            visible: Daemon.currentWallet.hasSeed
                            font.pixelSize: constants.fontSizeSmall
                            font.bold: true
                            iconSource: '../../../icons/seed.png'
                        }
                    }

                    GridLayout {
                        Layout.preferredWidth: parent.width
                        visible: Daemon.currentWallet
                        columns: 2

                        Label {
                            Layout.columnSpan: 2
                            Layout.topMargin: constants.paddingSmall
                            visible: Daemon.currentWallet.hasSeed
                            text: qsTr('Seed')
                            color: Material.accentColor
                        }

                        TextHighlightPane {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            visible: Daemon.currentWallet.hasSeed
                            RowLayout {
                                width: parent.width
                                Label {
                                    id: seedText
                                    visible: false
                                    Layout.fillWidth: true
                                    text: Daemon.currentWallet.seed
                                    wrapMode: Text.Wrap
                                    font.family: FixedFont
                                    font.pixelSize: constants.fontSizeMedium
                                }
                                Label {
                                    id: showSeedText
                                    Layout.fillWidth: true
                                    horizontalAlignment: Text.AlignHCenter
                                    text: qsTr('Tap to show seed')
                                    wrapMode: Text.Wrap
                                    font.pixelSize: constants.fontSizeLarge
                                }
                                MouseArea {
                                    anchors.fill: parent
                                    onClicked: {
                                        if (showSeedText.visible) {
                                            Daemon.currentWallet.requestShowSeed()
                                        } else {
                                            seedText.visible = false
                                            showSeedText.visible = true
                                        }
                                    }
                                }
                            }
                        }

                        Label {
                            id: seed_extension_label
                            Layout.columnSpan: 2
                            Layout.topMargin: constants.paddingSmall
                            visible: seedText.visible && Daemon.currentWallet.seedPassphrase
                            text: qsTr('Seed Extension')
                            color: Material.accentColor
                        }

                        TextHighlightPane {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            visible: seed_extension_label.visible
                            Label {
                                Layout.fillWidth: true
                                text: Daemon.currentWallet.seedPassphrase
                                wrapMode: Text.Wrap
                                font.family: FixedFont
                                font.pixelSize: constants.fontSizeMedium
                            }
                        }

                        Label {
                            Layout.columnSpan: 2
                            Layout.topMargin: constants.paddingSmall
                            visible: Daemon.currentWallet.isLightning
                            text: qsTr('Lightning Node ID')
                            color: Material.accentColor
                        }

                        TextHighlightPane {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            visible: Daemon.currentWallet.isLightning

                            RowLayout {
                                width: parent.width
                                Label {
                                    Layout.fillWidth: true
                                    text: Daemon.currentWallet.lightningNodePubkey
                                    wrapMode: Text.Wrap
                                    font.family: FixedFont
                                    font.pixelSize: constants.fontSizeMedium
                                }
                                ToolButton {
                                    icon.source: '../../icons/share.png'
                                    icon.color: 'transparent'
                                    onClicked: {
                                        var dialog = app.genericShareDialog.createObject(rootItem, {
                                            title: qsTr('Lightning Node ID'),
                                            text: Daemon.currentWallet.lightningNodePubkey
                                        })
                                        dialog.open()
                                    }
                                }
                            }
                        }

                        Label {
                            visible: _is2fa
                            text: qsTr('2FA')
                            color: Material.accentColor
                        }

                        Label {
                            Layout.fillWidth: true
                            visible: _is2fa
                            text: Daemon.currentWallet.canSignWithoutServer
                                    ? qsTr('disabled (can sign without server)')
                                    : qsTr('enabled')
                        }

                        Label {
                            visible: _is2fa && !Daemon.currentWallet.canSignWithoutServer
                            text: qsTr('Remaining TX')
                            color: Material.accentColor
                        }

                        Label {
                            Layout.fillWidth: true
                            visible: _is2fa && !Daemon.currentWallet.canSignWithoutServer
                            text: 'tx_remaining' in Daemon.currentWallet.billingInfo
                                    ? Daemon.currentWallet.billingInfo['tx_remaining']
                                    : qsTr('unknown')
                        }

                        Label {
                            Layout.columnSpan: 2
                            Layout.topMargin: constants.paddingSmall
                            visible: _is2fa && !Daemon.currentWallet.canSignWithoutServer
                            text: qsTr('Billing')
                            color: Material.accentColor
                        }

                        TextHighlightPane {
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            visible: _is2fa && !Daemon.currentWallet.canSignWithoutServer

                            ColumnLayout {
                                spacing: 0

                                ButtonGroup {
                                    id: billinggroup
                                    onCheckedButtonChanged: {
                                        Config.trustedcoinPrepay = checkedButton.value
                                    }
                                }

                                Repeater {
                                    model: AppController.plugin('trustedcoin').billingModel
                                    delegate: RowLayout {
                                        RadioButton {
                                            ButtonGroup.group: billinggroup
                                            property string value: modelData.value
                                            text: modelData.text
                                            checked: modelData.value == Config.trustedcoinPrepay
                                        }
                                        Label {
                                            text: Config.formatSats(modelData.sats_per_tx)
                                            font.family: FixedFont
                                        }
                                        Label {
                                            text: Config.baseUnit + '/tx'
                                            color: Material.accentColor
                                        }
                                    }
                                }
                            }
                        }

                        Repeater {
                            id: keystores
                            model: Daemon.currentWallet.keystores
                            delegate: ColumnLayout {
                                Layout.columnSpan: 2
                                Layout.topMargin: constants.paddingSmall
                                RowLayout {
                                    Label {
                                        text: qsTr('Keystore')
                                        color: Material.accentColor
                                    }
                                    Label {
                                        text: '#' + index
                                        visible: keystores.count > 1
                                    }
                                    Image {
                                        Layout.preferredWidth: constants.iconSizeXSmall
                                        Layout.preferredHeight: constants.iconSizeXSmall
                                        source: modelData.watch_only ? '../../icons/eye1.png' : '../../icons/key.png'
                                    }
                                }
                                TextHighlightPane {
                                    Layout.fillWidth: true
                                    leftPadding: constants.paddingLarge

                                    GridLayout {
                                        width: parent.width
                                        columns: 2

                                        Label {
                                            text: qsTr('Keystore type')
                                            visible: modelData.keystore_type
                                            color: Material.accentColor
                                        }
                                        Label {
                                            Layout.fillWidth: true
                                            text: modelData.keystore_type
                                            visible: modelData.keystore_type
                                        }

                                        Label {
                                            text: modelData.watch_only
                                                ? qsTr('Imported addresses')
                                                : qsTr('Imported keys')
                                            visible: modelData.num_imported
                                            color: Material.accentColor
                                        }
                                        Label {
                                            Layout.fillWidth: true
                                            text: modelData.num_imported
                                            visible: modelData.num_imported
                                        }

                                        Label {
                                            text: qsTr('Derivation prefix')
                                            visible: modelData.derivation_prefix
                                            color: Material.accentColor
                                        }
                                        Label {
                                            Layout.fillWidth: true
                                            text: modelData.derivation_prefix
                                            visible: modelData.derivation_prefix
                                            font.family: FixedFont
                                        }

                                        Label {
                                            text: qsTr('BIP32 fingerprint')
                                            visible: modelData.fingerprint
                                            color: Material.accentColor
                                        }
                                        Label {
                                            Layout.fillWidth: true
                                            text: modelData.fingerprint
                                            visible: modelData.fingerprint
                                            font.family: FixedFont
                                        }

                                        Label {
                                            Layout.columnSpan: 2
                                            visible: modelData.master_pubkey
                                            text: qsTr('Master Public Key')
                                            color: Material.accentColor
                                        }
                                        RowLayout {
                                            Layout.fillWidth: true
                                            Layout.columnSpan: 2
                                            Layout.leftMargin: constants.paddingLarge
                                            visible: modelData.master_pubkey
                                            Label {
                                                text: modelData.master_pubkey
                                                wrapMode: Text.Wrap
                                                Layout.fillWidth: true
                                                font.family: FixedFont
                                                font.pixelSize: constants.fontSizeMedium
                                            }
                                            ToolButton {
                                                icon.source: '../../icons/share.png'
                                                icon.color: 'transparent'
                                                onClicked: {
                                                    var dialog = app.genericShareDialog.createObject(rootItem, {
                                                        title: qsTr('Master Public Key'),
                                                        text: modelData.master_pubkey
                                                    })
                                                    dialog.open()
                                                }
                                            }
                                        }
                                    }
                                }
                            }
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
                text: qsTr('Delete Wallet')
                onClicked: Daemon.checkThenDeleteWallet(Daemon.currentWallet)
                icon.source: '../../icons/delete.png'
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Change Password')
                onClicked: Daemon.startChangePassword()
                icon.source: '../../icons/lock.png'
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                visible: Daemon.currentWallet.walletType == 'imported'
                text: Daemon.currentWallet.isWatchOnly
                        ? qsTr('Add addresses')
                        : qsTr('Add keys')
                icon.source: '../../icons/add.png'
                onClicked: rootItem.importAddressesKeys()
            }
            FlatButton {
                Layout.fillWidth: true
                Layout.preferredWidth: 1
                text: qsTr('Enable Lightning')
                onClicked: rootItem.enableLightning()
                visible: Daemon.currentWallet && Daemon.currentWallet.canHaveLightning && !Daemon.currentWallet.isLightning
                icon.source: '../../icons/lightning.png'
            }
        }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            Daemon.availableWallets.reload()
            app.stack.pop()
        }
        function onRequestNewPassword() { // new unified password (all wallets)
            var dialog = app.passwordDialog.createObject(app, {
                confirmPassword: true,
                title: qsTr('Enter new password'),
                infotext: qsTr('If you forget your password, you\'ll need to restore from seed. Please make sure you have your seed stored safely')
            })
            dialog.accepted.connect(function() {
                var success = Daemon.setPassword(dialog.password)
                var done_dialog = app.messageDialog.createObject(app, {
                    title: success ? qsTr('Success') : qsTr('Error'),
                    iconSource: success
                        ? Qt.resolvedUrl('../../icons/info.png')
                        : Qt.resolvedUrl('../../icons/warning.png'),
                    text: success ? qsTr('Password changed') : qsTr('Password change failed')
                })
                done_dialog.open()
            })
            dialog.open()
        }
        function onWalletDeleteError(code, message) {
            if (code == 'unpaid_requests') {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTr('Warning'),
                    text: message,
                    yesno: true
                })
                dialog.accepted.connect(function() {
                    Daemon.checkThenDeleteWallet(Daemon.currentWallet, true)
                })
                dialog.open()
            } else if (code == 'balance') {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTr('Warning'),
                    text: message,
                    yesno: true
                })
                dialog.accepted.connect(function() {
                    Daemon.checkThenDeleteWallet(Daemon.currentWallet, true, true)
                })
                dialog.open()
            } else {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTr('Error'),
                    iconSource: Qt.resolvedUrl('../../icons/warning.png'),
                    text: message
                })
                dialog.open()
            }
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestNewPassword() { // new wallet password
            var dialog = app.passwordDialog.createObject(app, {
                confirmPassword: true,
                title: qsTr('Enter new password'),
                infotext: qsTr('If you forget your password, you\'ll need to restore from seed. Please make sure you have your seed stored safely')
            })
            dialog.accepted.connect(function() {
                var success = Daemon.currentWallet.setPassword(dialog.password)
                var done_dialog = app.messageDialog.createObject(app, {
                    title: success ? qsTr('Success') : qsTr('Error'),
                    iconSource: success
                        ? Qt.resolvedUrl('../../icons/info.png')
                        : Qt.resolvedUrl('../../icons/warning.png'),
                    text: success ? qsTr('Password changed') : qsTr('Password change failed')
                })
                done_dialog.open()
            })
            dialog.open()
        }
        function onSeedRetrieved() {
            seedText.visible = true
            showSeedText.visible = false
        }
    }

    Component {
        id: importAddressesKeysDialog
        ImportAddressesKeysDialog {
            width: parent.width
            height: parent.height
            onClosed: destroy()
        }
    }

    Binding {
        target: AppController
        property: 'secureWindow'
        value: seedText.visible
    }

}
