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

            Heading {
                text: qsTr('Wallets')
            }

            TextField {
                id: searchEdit
                Layout.fillWidth: true
                Layout.leftMargin: constants.paddingLarge
                Layout.rightMargin: constants.paddingLarge

                placeholderText: qsTr('search')
                inputMethodHints: Qt.ImhNoPredictiveText
                EnterKey.type: Qt.EnterKeyDone
                onAccepted: {
                    // load a wallet (e.g. a hidden wallet not shown in the list) when
                    // the search text exactly matches an available wallet name
                    var path = Daemon.availableWallets.pathForName(text)
                    if (path && !Daemon.loading) {
                        if (!Daemon.currentWallet || Daemon.currentWallet.name != text) {
                            Daemon.loadWallet(path)
                        } else {
                            app.stack.pop()
                        }
                    }
                }

                Image {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.rightMargin: constants.paddingMedium
                    source: Qt.resolvedUrl('../../icons/zoom.png')
                    sourceSize.width: constants.iconSizeMedium
                    sourceSize.height: constants.iconSizeMedium
                }
            }

            Frame {
                id: detailsFrame
                Layout.fillWidth: true
                Layout.fillHeight: true
                verticalPadding: bg.lineWidth
                horizontalPadding: 0
                background: PaneInsetBackground { id: bg; vertical: false }

                ElListView {
                    id: listview
                    anchors.fill: parent
                    clip: true
                    model: Daemon.availableWallets

                    delegate: ItemDelegate {
                        property bool matchesSearch: searchEdit.text.length === 0
                            || model.name.toLowerCase().indexOf(searchEdit.text.toLowerCase()) !== -1
                        property bool hiddenWallet: model.name.startsWith('.') && !model.active
                        width: ListView.view.width
                        height: visible ? row.height : 0
                        // visible: searchEdit.text.length === 0
                        //     || model.name.toLowerCase().indexOf(searchEdit.text.toLowerCase()) !== -1
                        visible: matchesSearch && !hiddenWallet
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

        ButtonContainer {
            Layout.fillWidth: true
            visible: !searchEdit.text

            FlatButton {
                Layout.fillWidth: true
                text: qsTr('Create Wallet')
                icon.source: '../../icons/add.png'
                onClicked: {
                    if (Daemon.availableWallets.rowCount() > 0 && Config.walletShouldUseSinglePassword
                        && (!Daemon.singlePassword || Daemon.numWalletsWithPassword(Daemon.singlePassword) < 1)) {
                        // if the user has wallets but hasn't unlocked any wallet yet force them to do so.
                        // this ensures they know at least one wallets password and can complete the wizard
                        // where they will need to enter the password of an existing wallet.
                        var dialog = app.messageDialog.createObject(app, {
                            title: qsTr('Wallet unlock required'),
                            text: qsTr("You have to unlock any existing wallet first before creating a new wallet."),
                        })
                        dialog.open()
                    } else {
                        rootItem.createWallet()
                    }
                }
            }
        }
    }
    property color navigationBarBackgroundColor: constants.highlightBackground

    Connections {
        target: Daemon
        function onWalletLoaded() {
            if (app.stack.currentItem.objectName == 'Wallets')
                if (app.stack.getRoot().objectName == 'Wallets') {
                    app.stack.replaceRoot('WalletMainView.qml')
                } else {
                    app.stack.pop()
                }
        }
    }

}
