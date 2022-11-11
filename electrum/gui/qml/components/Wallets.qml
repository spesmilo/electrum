import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem
    objectName: 'Wallets'

    padding: 0

    function createWallet() {
        var dialog = app.newWalletWizard.createObject(rootItem)
        dialog.open()
        dialog.walletCreated.connect(function() {
            Daemon.availableWallets.reload()
            // and load the new wallet
            Daemon.load_wallet(dialog.path, dialog.wizard_data['password'])
        })
    }

    ColumnLayout {
        id: rootLayout
        width: parent.width
        height: parent.height
        spacing: 0

        ColumnLayout {
            Layout.preferredWidth: parent.width
            Layout.margins: constants.paddingLarge

            Label {
                text: qsTr('Wallets')
                font.pixelSize: constants.fontSizeLarge
                color: Material.accentColor
            }

            Rectangle {
                Layout.fillWidth: true
                height: 1
                color: Material.accentColor
            }

            Frame {
                id: detailsFrame
                Layout.preferredWidth: parent.width
                Layout.fillHeight: true
                verticalPadding: 0
                horizontalPadding: 0
                background: PaneInsetBackground {}

                ListView {
                    id: listview
                    anchors.fill: parent
                    clip: true
                    model: Daemon.availableWallets

                    delegate: ItemDelegate {
                        width: ListView.view.width
                        height: row.height

                        onClicked: {
                            Daemon.load_wallet(model.path)
                        }

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
                                Layout.topMargin: constants.paddingSmall
                                Layout.bottomMargin: constants.paddingSmall
                            }

                            Label {
                                font.pixelSize: constants.fontSizeLarge
                                text: model.name
                                color: model.active ? Material.foreground : Qt.darker(Material.foreground, 1.20)
                                Layout.fillWidth: true
                            }

                            Tag {
                                visible: Daemon.currentWallet && model.name == Daemon.currentWallet.name
                                text: qsTr('Current')
                                border.color: Material.foreground
                                font.bold: true
                                labelcolor: Material.foreground
                            }
                            Tag {
                                visible: model.active
                                text: qsTr('Active')
                                border.color: 'green'
                                labelcolor: 'green'
                            }
                            Tag {
                                visible: !model.active
                                text: qsTr('Not loaded')
                                border.color: 'grey'
                                labelcolor: 'grey'
                            }
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }
                }
            }

        }

        FlatButton {
            Layout.fillWidth: true
            text: 'Create Wallet'
            onClicked: rootItem.createWallet()
        }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            Daemon.availableWallets.reload()
            app.stack.pop()
        }
    }

}
