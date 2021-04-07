import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0

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
                    Label { text: Daemon.walletName; Layout.columnSpan: 2 }

                    Label { text: 'txinType' }
                    Label { text: Daemon.currentWallet.txinType }

                    Label { text: 'is deterministic' }
                    Label { text: Daemon.currentWallet.isDeterministic }

                    Label { text: 'is watch only' }
                    Label { text: Daemon.currentWallet.isWatchOnly }

                    Label { text: 'is Encrypted' }
                    Label { text: Daemon.currentWallet.isEncrypted }

                    Label { text: 'is Hardware' }
                    Label { text: Daemon.currentWallet.isHardware }

                    Label { text: 'derivation path (BIP32)'; visible: Daemon.currentWallet.isDeterministic }
                    Label { text: Daemon.currentWallet.derivationPath; visible: Daemon.currentWallet.isDeterministic }
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
            clip:true
            model: Daemon.availableWallets

            // header: sadly seems to be buggy

            delegate: AbstractButton {
                width: ListView.view.width
                height: 50
                onClicked: console.log('delegate clicked')
                RowLayout {
                    x: 20
                    spacing: 20

                    Image {
                        source: "../../../gui/kivy/theming/light/wallet.png"
                    }

                    Label {
                        font.pointSize: 12
                        text: model.name
                        Layout.fillWidth: true
                    }
                    Button {
                        text: 'Load'
                        onClicked: {
                            Daemon.load_wallet(model.path, null)
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
            }
        }
    }
}
