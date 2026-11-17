import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// "Wallets" of the Material 3 GUI: the root of the stack while no wallet is open (main.qml initialItem, and
// replaceRoot('Wallets.qml') after a wallet was deleted) and the page of the route app.routes.wallets (overflow
// menu "Wallets"). Same file name and objectName as the classic page: main.qml and the classic code find it by both.
// repeats: components/Wallets.qml:10-195 @ e6df7e1c8 (objectName 'Wallets', the title, createWallet() with
// app.newWalletWizard and walletCreated, the search field whose exact match loads a wallet not shown in the list,
// the list of Daemon.availableWallets: a row is shown when it matches the search and is not a hidden wallet
// (name starting with '.', not loaded), a tap loads it or goes back when it is the current one; "Create Wallet"
// only while the search is empty, with the check that an existing wallet was unlocked first when all wallets use
// one password; on Daemon.walletLoaded: the wallet screen as the new root, or back).
// Look (DESIGN-M2-onboarding.md 5.1): M3Page, the search as M3TextField, the list in a surfaceContainerLow
// container (empty space when there are no wallets, as the empty classic frame), a row = M3ListItem with an
// avatar (first letter; primaryContainer when loaded), "Active" / "Not loaded" as the second line and the
// "Current" pill on the right; "Create Wallet" in the action bar below the list. The heading of the classic page
// is the title of the page (top app bar).
// Strings carried over keep the translation context of Wallets.qml.
M3Page {
    id: rootItem
    objectName: 'Wallets'

    title: qsTranslate('Wallets', 'Wallets')

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
            id: column
            readonly property int margin: m3.screenMargin(rootItem.width)
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.maximumWidth: m3.maxContentWidth
            Layout.alignment: Qt.AlignHCenter
            Layout.leftMargin: margin
            Layout.rightMargin: margin
            Layout.topMargin: m3.space16
            spacing: m3.space16

            M3TextField {
                id: searchEdit
                Layout.fillWidth: true

                label: qsTranslate('Wallets', 'search')
                inputMethodHints: Qt.ImhNoPredictiveText
                field.EnterKey.type: Qt.EnterKeyDone
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
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.bottomMargin: m3.space8
                // no wallets (a fresh install after the wizard was cancelled): empty space above the button
                color: listview.count > 0 ? m3.surfaceContainerLow : 'transparent'
                radius: m3.radiusL
                clip: true

                ListView {
                    id: listview
                    anchors.fill: parent
                    anchors.topMargin: m3.space8
                    anchors.bottomMargin: m3.space8
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    model: Daemon.availableWallets

                    delegate: Item {
                        id: walletItem
                        property bool matchesSearch: searchEdit.text.length === 0
                            || model.name.toLowerCase().indexOf(searchEdit.text.toLowerCase()) !== -1
                        property bool hiddenWallet: model.name.startsWith('.') && !model.active
                        width: ListView.view.width
                        height: visible ? walletRow.implicitHeight : 0
                        visible: matchesSearch && !hiddenWallet

                        M3ListItem {
                            id: walletRow
                            readonly property bool isCurrent: Daemon.currentWallet != null
                                && model.name == Daemon.currentWallet.name
                            readonly property bool isActive: model.active
                            readonly property string walletName: model.name

                            width: parent.width

                            headline: model.name
                            supporting: model.active
                                ? qsTranslate('Wallets', 'Active')
                                : qsTranslate('Wallets', 'Not loaded')

                            onClicked: {
                                if (!Daemon.currentWallet || Daemon.currentWallet.name != model.name) {
                                    if (!Daemon.loading) // wallet load in progress
                                        Daemon.loadWallet(model.path)
                                } else {
                                    app.stack.pop()
                                }
                            }

                            leading: Component {
                                Rectangle {
                                    implicitWidth: 40
                                    implicitHeight: 40
                                    radius: 20
                                    color: walletRow.isActive ? m3.primaryContainer : m3.surfaceContainerHighest
                                    M3Text {
                                        anchors.centerIn: parent
                                        role: 'titleMedium'
                                        color: walletRow.isActive ? m3.primaryContainerOn : m3.surfaceVariantOn
                                        text: walletRow.walletName.replace(/^\./, '').charAt(0).toUpperCase()
                                    }
                                }
                            }

                            trailing: walletRow.isCurrent ? currentTag : null
                        }
                    }

                    ScrollIndicator.vertical: ScrollIndicator { }
                }
            }
        }

        // the main action below the list, above the keyboard (the page shrinks with the keyboard)
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface
            visible: !searchEdit.text

            RowLayout {
                id: actions
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)

                Item { Layout.fillWidth: true }
                M3Button {
                    variant: 'filled'
                    text: qsTranslate('Wallets', 'Create Wallet')
                    icon.source: Qt.resolvedUrl('../../icons/m3/add.png')
                    onClicked: {
                        if (Daemon.availableWallets.rowCount() > 0 && Config.walletShouldUseSinglePassword
                            && (!Daemon.singlePassword || Daemon.numWalletsWithPassword(Daemon.singlePassword) < 1)) {
                            // if the user has wallets but hasn't unlocked any wallet yet force them to do so.
                            // this ensures they know at least one wallets password and can complete the wizard
                            // where they will need to enter the password of an existing wallet.
                            var dialog = app.messageDialog.createObject(app, {
                                title: qsTranslate('Wallets', 'Wallet unlock required'),
                                text: qsTranslate('Wallets', "You have to unlock any existing wallet first before creating a new wallet."),
                            })
                            dialog.open()
                        } else {
                            rootItem.createWallet()
                        }
                    }
                }
            }
        }
    }

    Component {
        id: currentTag
        // the "Current" pill of the current wallet
        Rectangle {
            implicitWidth: tagText.implicitWidth + 2 * m3.space12
            implicitHeight: tagText.implicitHeight + 2 * m3.space4
            radius: height / 2
            color: m3.secondaryContainer
            M3Text {
                id: tagText
                anchors.centerIn: parent
                role: 'labelMedium'
                color: m3.secondaryContainerOn
                text: qsTranslate('Wallets', 'Current')
            }
        }
    }

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
