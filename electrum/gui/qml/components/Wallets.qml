import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem

    property string title: qsTr('Wallets')

    function createWallet() {
        var dialog = app.newWalletWizard.createObject(rootItem)
        dialog.open()
        dialog.walletCreated.connect(function() {
            Daemon.availableWallets.reload()
            // and load the new wallet
            Daemon.load_wallet(dialog.path, dialog.wizard_data['password'])
        })
    }

    function enableLightning() {
        var dialog = app.messageDialog.createObject(rootItem,
                {'text': qsTr('Enable Lightning for this wallet?'), 'yesno': true})
        dialog.yesClicked.connect(function() {
            Daemon.currentWallet.enableLightning()
        })
        dialog.open()
    }

    function deleteWallet() {
        var dialog = app.messageDialog.createObject(rootItem,
                {'text': qsTr('Really delete this wallet?'), 'yesno': true})
        dialog.yesClicked.connect(function() {
            Daemon.currentWallet.deleteWallet()
        })
        dialog.open()
    }

    property QtObject menu: Menu {
        id: menu
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Create Wallet');
                onTriggered: rootItem.createWallet()
                icon.source: '../../icons/wallet.png'
            }
        }
        Component {
            id: changePasswordComp
            MenuItem {
                icon.color: 'transparent'
                enabled: false
                action: Action {
                    text: qsTr('Change Password');
                    onTriggered: rootItem.changePassword()
                    icon.source: '../../icons/lock.png'
                }
            }
        }
        Component {
            id: deleteWalletComp
            MenuItem {
                icon.color: 'transparent'
                enabled: false
                action: Action {
                    text: qsTr('Delete Wallet');
                    onTriggered: rootItem.deleteWallet()
                    icon.source: '../../icons/delete.png'
                }
            }
        }

        Component {
            id: enableLightningComp
            MenuItem {
                icon.color: 'transparent'
                action: Action {
                    text: qsTr('Enable Lightning');
                    onTriggered: rootItem.enableLightning()
                    enabled: Daemon.currentWallet != null && Daemon.currentWallet.canHaveLightning && !Daemon.currentWallet.isLightning
                    icon.source: '../../icons/lightning.png'
                }
            }
        }

        Component {
            id: sepComp
            MenuSeparator {}
        }

        // add items dynamically, if using visible: false property the menu item isn't removed but empty
        Component.onCompleted: {
            if (Daemon.currentWallet != null) {
                menu.insertItem(0, sepComp.createObject(menu))
                if (Daemon.currentWallet.canHaveLightning && !Daemon.currentWallet.isLightning) {
                    menu.insertItem(0, enableLightningComp.createObject(menu))
                }
                menu.insertItem(0, deleteWalletComp.createObject(menu))
                menu.insertItem(0, changePasswordComp.createObject(menu))
            }
        }
    }

    ColumnLayout {
        id: layout
        width: parent.width
        height: parent.height

        GridLayout {
            id: detailsLayout
            visible: Daemon.currentWallet != null
            Layout.preferredWidth: parent.width

            columns: 4

            Label { text: 'Wallet'; Layout.columnSpan: 2; color: Material.accentColor }
            Label { text: Daemon.currentWallet.name; font.bold: true /*pixelSize: constants.fontSizeLarge*/; Layout.columnSpan: 2 }

            Label { text: 'derivation prefix (BIP32)'; visible: Daemon.currentWallet.isDeterministic; color: Material.accentColor; Layout.columnSpan: 2 }
            Label { text: Daemon.currentWallet.derivationPrefix; visible: Daemon.currentWallet.isDeterministic; Layout.columnSpan: 2 }

            Label { text: 'txinType'; color: Material.accentColor }
            Label { text: Daemon.currentWallet.txinType }

            Label { text: 'is deterministic'; color: Material.accentColor }
            Label { text: Daemon.currentWallet.isDeterministic }

            Label { text: 'is watch only'; color: Material.accentColor }
            Label { text: Daemon.currentWallet.isWatchOnly }

            Label { text: 'is Encrypted'; color: Material.accentColor }
            Label { text: Daemon.currentWallet.isEncrypted }

            Label { text: 'is Hardware'; color: Material.accentColor }
            Label { text: Daemon.currentWallet.isHardware }

            Label { text: 'is Lightning'; color: Material.accentColor }
            Label { text: Daemon.currentWallet.isLightning }

            Label { text: 'has Seed'; color: Material.accentColor }
            Label { text: Daemon.currentWallet.hasSeed; Layout.columnSpan: 3 }

            Label { Layout.columnSpan:4; text: qsTr('Master Public Key'); color: Material.accentColor }

            TextHighlightPane {
                Layout.columnSpan: 4
                Layout.fillWidth: true
                padding: 0
                leftPadding: constants.paddingSmall

                RowLayout {
                    width: parent.width
                    Label {
                        text: Daemon.currentWallet.masterPubkey
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                        font.family: FixedFont
                        font.pixelSize: constants.fontSizeMedium
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: 'transparent'
                        onClicked: {
                            var dialog = share.createObject(rootItem, {
                                'title': qsTr('Master Public Key'),
                                'text': Daemon.currentWallet.masterPubkey
                            })
                            dialog.open()
                        }
                    }
                }
            }
        }

        ColumnLayout {
            visible: Daemon.currentWallet == null

            Layout.alignment: Qt.AlignHCenter
            Layout.bottomMargin: constants.paddingXXLarge
            Layout.topMargin: constants.paddingXXLarge
            spacing: 2*constants.paddingXLarge

            Label {
                text: qsTr('No wallet loaded')
                font.pixelSize: constants.fontSizeXXLarge
                Layout.alignment: Qt.AlignHCenter
            }

        }

        Frame {
            id: detailsFrame
            Layout.topMargin: constants.paddingXLarge
            Layout.preferredWidth: parent.width
            Layout.fillHeight: true
            verticalPadding: 0
            horizontalPadding: 0
            background: PaneInsetBackground {}

            ColumnLayout {
                spacing: 0
                anchors.fill: parent

                Item {
                    Layout.preferredHeight: hitem.height
                    Layout.preferredWidth: parent.width
                    Rectangle {
                        anchors.fill: parent
                        color: Qt.lighter(Material.background, 1.25)
                    }
                    RowLayout {
                        id: hitem
                        width: parent.width
                        Label {
                            text: qsTr('Available wallets')
                            font.pixelSize: constants.fontSizeLarge
                            color: Material.accentColor
                        }
                    }
                }

                ListView {
                    id: listview
                    Layout.preferredWidth: parent.width
                    Layout.fillHeight: true
                    clip: true
                    model: Daemon.availableWallets

                    delegate: AbstractButton {
                        width: ListView.view.width
                        height: row.height

                        RowLayout {
                            id: row
                            spacing: 10
                            x: constants.paddingSmall
                            width: parent.width - 2 * constants.paddingSmall

                            Image {
                                id: walleticon
                                source: "../../icons/wallet.png"
                                fillMode: Image.PreserveAspectFit
                                Layout.preferredWidth: constants.iconSizeLarge
                                Layout.preferredHeight: constants.iconSizeLarge
                            }

                            Label {
                                font.pixelSize: constants.fontSizeLarge
                                text: model.name
                                Layout.fillWidth: true
                            }

                            Button {
                                text: 'Open'
                                onClicked: {
                                    Daemon.load_wallet(model.path)
                                }
                            }
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }
                }
            }
        }

        Button {
            Layout.alignment: Qt.AlignHCenter
            text: 'Create Wallet'
            onClicked: rootItem.createWallet()
        }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            app.stack.pop()
        }
    }

    Component {
        id: share
        GenericShareDialog {
            onClosed: destroy()
        }
    }
}
