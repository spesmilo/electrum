import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: rootItem
    objectName: 'Wallets'

    padding: 0

    property string title: qsTr('Wallets')

    function createWallet() {
        var dialog = app.newWalletWizard.createObject(app)
        dialog.open()
        dialog.walletCreated.connect(function() {
            Daemon.availableWallets.reload()
            // and load the new wallet
            Daemon.loadWallet(dialog.path, dialog.wizard_data['password'])
        })
    }

    ColumnLayout {
        id: rootLayout
        anchors.fill: parent
        spacing: 0

        ColumnLayout {
            Layout.fillWidth: true
            Layout.margins: constants.paddingLarge

            Heading {
                text: qsTr('Wallets')
            }

            Frame {
                id: detailsFrame
                Layout.fillWidth: true
                Layout.fillHeight: true
                verticalPadding: 0
                horizontalPadding: 0
                background: PaneInsetBackground {}

                ElListView {
                    id: listview
                    anchors.fill: parent
                    clip: true
                    model: Daemon.availableWallets

                    delegate: ItemDelegate {
                        width: ListView.view.width
                        height: row.height

                        onClicked: {
                            if (!Daemon.currentWallet || Daemon.currentWallet.name != model.name) {
                                if (!Daemon.loading) // wallet load in progress
                                    Daemon.loadWallet(model.path)
                            } else {
                                app.stack.pop()
                            }
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
                                Layout.fillWidth: true
                                font.pixelSize: constants.fontSizeLarge
                                text: model.name
                                elide: Label.ElideRight
                                color: model.active ? Material.foreground : Qt.darker(Material.foreground, 1.20)
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
            text: qsTr('Create Wallet')
            icon.source: '../../icons/add.png'
            onClicked: rootItem.createWallet()
        }
    }

    Connections {
        target: Daemon
        function onWalletLoaded() {
            if (app.stack.currentItem.objectName == 'Wallets')
                app.stack.pop()
        }
    }

}
