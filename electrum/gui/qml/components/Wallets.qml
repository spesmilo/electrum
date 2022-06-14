import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem

    property string title: qsTr('Wallets')

    ColumnLayout {
        id: layout
        width: parent.width
        height: parent.height

        GridLayout {
            id: detailsLayout
            Layout.preferredWidth: parent.width

            columns: 4

            Label { text: 'Wallet'; Layout.columnSpan: 2; color: Material.accentColor }
            Label { text: Daemon.currentWallet.name; Layout.columnSpan: 2 }

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
            Label { text: Daemon.currentWallet.hasSeed }

            RowLayout {
                visible: !Daemon.currentWallet.isLightning && Daemon.currentWallet.canHaveLightning
                Layout.columnSpan: 2
                Layout.alignment: Qt.AlignHCenter

                Button {
                    enabled: Daemon.currentWallet.canHaveLightning && !Daemon.currentWallet.isLightning
                    text: qsTr('Enable Lightning')
                    onClicked: Daemon.currentWallet.enableLightning()
                }
            }

            Item {
                visible: Daemon.currentWallet.isLightning || !Daemon.currentWallet.canHaveLightning
                Layout.columnSpan: 2
                Layout.preferredHeight: 1
                Layout.preferredWidth: 1
            }

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

        Item { width: 1; height: 1 }

        Frame {
            id: detailsFrame
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

    Component {
        id: share
        GenericShareDialog {
            onClosed: destroy()
        }
    }
}
