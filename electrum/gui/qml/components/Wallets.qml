import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem

    property string title: 'Wallets'

    ColumnLayout {
        id: layout
        width: parent.width
        height: parent.height

        Item {
            width: parent.width
            height: detailsLayout.height


                GridLayout {
                    id: detailsLayout
                    width: parent.width
                    columns: 4

                    Label { text: 'Wallet'; Layout.columnSpan: 2 }
                    Label { text: Daemon.walletName; Layout.columnSpan: 2; color: Material.accentColor }

                    Label { text: 'derivation path (BIP32)'; visible: Daemon.currentWallet.isDeterministic; Layout.columnSpan: 2 }
                    Label { text: Daemon.currentWallet.derivationPath; visible: Daemon.currentWallet.isDeterministic; color: Material.accentColor; Layout.columnSpan: 2 }

                    Label { text: 'txinType' }
                    Label { text: Daemon.currentWallet.txinType; color: Material.accentColor }

                    Label { text: 'is deterministic' }
                    Label { text: Daemon.currentWallet.isDeterministic; color: Material.accentColor }

                    Label { text: 'is watch only' }
                    Label { text: Daemon.currentWallet.isWatchOnly; color: Material.accentColor }

                    Label { text: 'is Encrypted' }
                    Label { text: Daemon.currentWallet.isEncrypted; color: Material.accentColor }

                    Label { text: 'is Hardware' }
                    Label { text: Daemon.currentWallet.isHardware; color: Material.accentColor }
                }
            }
//        }

        Item {
            width: parent.width
//            height: detailsFrame.height
            Layout.fillHeight: true
        Frame {
            id: detailsFrame
            width: parent.width
            height: parent.height

        ListView {
            id: listview
            width: parent.width
//            Layout.fillHeight: true
            height: parent.height
            clip: true
            model: Daemon.availableWallets

            // header: sadly seems to be buggy

            delegate: AbstractButton {
                width: ListView.view.width
                height: 50
                onClicked: {
                    wallet_db.path = model.path
                }

                RowLayout {
                    spacing: 10
                    width: parent.width

                    Image {
                        id: walleticon
                        source: "../../icons/wallet.png"
                        fillMode: Image.PreserveAspectFit
                        Layout.preferredWidth: 32
                        Layout.preferredHeight: 32
                    }

                    Label {
                        font.pixelSize: 18
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
        }}}

        Button {
            Layout.alignment: Qt.AlignHCenter
            text: 'Create Wallet'
            onClicked:  {
                var dialog = app.newWalletWizard.createObject(rootItem)
                dialog.open()
                dialog.walletCreated.connect(function() {
                    Daemon.availableWallets.reload()
                    // and load the new wallet
                    Daemon.load_wallet(dialog.path, dialog.wizard_data['password'])
                })
            }
        }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            app.stack.pop()
        }
    }

    WalletDB {
        id: wallet_db
    }
}
