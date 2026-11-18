import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Address details of the Material 3 GUI (route app.routes.addressDetails, replaces the classic AddressDetails; also
// opened from the inputs and outputs of the transaction details).
// repeats: components/AddressDetails.qml:10-369 @ e6df7e1c8: the page contract (`address`, the signals
// addressDetailsChanged and addressDeleted, which the address list connects to), the frozen mark, the address and
// its share dialog, balance, number of transactions and the address history (the route addressHistory with
// `address` and `backingModel` = the history model of the address), the label and its editing, script type,
// derivation path, public key(s) with their share dialogs, the private key (not for watch-only wallets) shown only
// after requestShowPrivateKey() (the wallet asks for authentication, app.handleAuthRequired) and its share dialog,
// Freeze / Unfreeze, Sign/Verify (app.signVerifyMessageDialog with `address`, when the wallet can sign), Delete
// with its confirmation (when the address can be deleted), the AddressDetails object and its handlers, the secure
// window while the private key is shown. Only the look differs.
// Layout (M2-MAP F-3, F-4): details are M3DetailRow rows; Freeze and Sign/Verify are buttons below the content;
// Delete (rare and destructive) is in the overflow menu of the top app bar (`m3Actions`).
// Strings keep the translation context of the classic file (qsTranslate('AddressDetails', ...)).
M3Page {
    id: root

    property string address

    signal addressDetailsChanged
    signal addressDeleted

    title: qsTranslate('AddressDetails', 'Address details')

    // AddressDetails.qml:321-341 (Delete): the overflow menu of the top app bar (as WalletDetailsPage)
    property list<Item> m3Actions: [
        M3IconButton {
            visible: addressdetails.canDelete
            tooltip: qsTr('More options')
            icon.source: Qt.resolvedUrl('../../icons/m3/more_vert.png')
            onClicked: overflowMenu.open()
        }
    ]

    // AddressDetails.qml:326-339
    function deleteAddress() {
        var confirmdialog = app.messageDialog.createObject(root, {
            text: qsTranslate('AddressDetails', 'Are you sure you want to delete this address from the wallet?'),
            yesno: true
        })
        confirmdialog.accepted.connect(function () {
            var success = addressdetails.deleteAddress()
            if (success) {
                addressDeleted()
                app.stack.pop()
            }
        })
        confirmdialog.open()
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        Flickable {
            id: flickable
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentHeight: content.implicitHeight + 2 * m3.space16
            interactive: height < contentHeight
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: content
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                // --- the frozen mark (AddressDetails.qml:48-60) ---
                M3Chip {
                    visible: addressdetails.isFrozen
                    focusPolicy: Qt.NoFocus
                    hoverEnabled: false
                    tone: 'tertiary'
                    iconSource: Qt.resolvedUrl('../../icons/m3/ac_unit.png')
                    text: qsTranslate('AddressDetails', 'Frozen')
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    // AddressDetails.qml:48-86
                    M3DetailRow {
                        label: qsTranslate('AddressDetails', 'Address')
                        text: root.address
                        monospace: true
                        shareable: true
                        shareTitle: qsTranslate('AddressDetails', 'Address')
                    }

                    // AddressDetails.qml:88-95
                    Item {
                        Layout.fillWidth: true
                        implicitHeight: Math.max(56, balanceLayout.implicitHeight + 2 * m3.space8)

                        ColumnLayout {
                            id: balanceLayout
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: m3.space16
                            anchors.rightMargin: m3.space16
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 2

                            M3Text {
                                Layout.fillWidth: true
                                role: 'bodySmall'
                                color: m3.surfaceVariantOn
                                text: qsTranslate('AddressDetails', 'Balance')
                            }
                            M3Amount {
                                amount: addressdetails.balance
                                fiatBelow: false
                            }
                        }
                    }

                    // AddressDetails.qml:97-116: the history of the address (only when it has transactions)
                    M3DetailRow {
                        label: qsTranslate('AddressDetails', 'Transactions')
                        text: addressdetails.numTx
                        actions: [
                            M3IconButton {
                                visible: addressdetails.numTx
                                tooltip: qsTranslate('AddressDetails', 'show...')
                                icon.source: Qt.resolvedUrl('../../icons/m3/history.png')
                                onClicked: root.showHistory()
                            }
                        ]
                    }

                    // --- label (AddressDetails.qml:118-175) ---
                    M3DetailRow {
                        id: labelRow
                        visible: !labelEditRow.editmode
                        label: qsTranslate('AddressDetails', 'Label')
                        text: addressdetails.label
                        actions: [
                            M3IconButton {
                                tooltip: qsTr('Edit')
                                icon.source: Qt.resolvedUrl('../../icons/m3/edit.png')
                                onClicked: {
                                    labelEdit.text = addressdetails.label
                                    labelEditRow.editmode = true
                                    labelEdit.field.forceActiveFocus()
                                }
                            }
                        ]
                    }

                    Item {
                        id: labelEditRow
                        property bool editmode: false
                        Layout.fillWidth: true
                        visible: editmode
                        implicitHeight: labelEditLayout.implicitHeight + 2 * m3.space8

                        RowLayout {
                            id: labelEditLayout
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: m3.space16
                            anchors.rightMargin: m3.space4
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 0

                            M3TextField {
                                id: labelEdit
                                Layout.fillWidth: true
                                label: qsTranslate('AddressDetails', 'Label')
                                text: addressdetails.label
                            }
                            M3IconButton {
                                tooltip: qsTr('Save')
                                icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
                                icon.color: m3.primary
                                onClicked: {
                                    labelEditRow.editmode = false
                                    addressdetails.setLabel(labelEdit.text)
                                }
                            }
                            M3IconButton {
                                tooltip: qsTr('Cancel')
                                icon.source: Qt.resolvedUrl('../../icons/m3/close.png')
                                onClicked: labelEditRow.editmode = false
                            }
                        }
                    }
                }

                // --- technical properties (AddressDetails.qml:177-295) ---
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    text: qsTranslate('AddressDetails', 'Technical Properties')
                }

                M3ListGroup {
                    Layout.fillWidth: true

                    M3DetailRow {
                        label: qsTranslate('AddressDetails', 'Script type')
                        text: addressdetails.scriptType
                    }

                    M3DetailRow {
                        visible: addressdetails.derivationPath
                        label: qsTranslate('AddressDetails', 'Derivation path')
                        text: addressdetails.derivationPath
                    }

                    Repeater {
                        model: addressdetails.pubkeys
                        delegate: M3DetailRow {
                            required property string modelData
                            label: addressdetails.pubkeys.length > 1
                                ? qsTranslate('AddressDetails', 'Public keys')
                                : qsTranslate('AddressDetails', 'Public key')
                            text: modelData
                            monospace: true
                            shareable: modelData
                            shareTitle: qsTranslate('AddressDetails', 'Public key')
                        }
                    }

                    // the private key, once shown (AddressDetails.qml:245-287)
                    M3DetailRow {
                        visible: !Daemon.currentWallet.isWatchOnly && addressdetails.privkey
                        label: qsTranslate('AddressDetails', 'Private key')
                        text: addressdetails.privkey
                        monospace: true
                        shareable: true
                        shareTitle: qsTranslate('AddressDetails', 'Private key')
                    }

                    // "Tap to show private key" (AddressDetails.qml:268-293)
                    M3ListItem {
                        visible: !Daemon.currentWallet.isWatchOnly && !addressdetails.privkey
                        leadingIcon: Qt.resolvedUrl('../../icons/m3/key.png')
                        headline: qsTranslate('AddressDetails', 'Private key')
                        supporting: qsTranslate('AddressDetails', 'Tap to show private key')
                        onClicked: addressdetails.requestShowPrivateKey()
                    }
                }
            }
        }

        // --- Freeze and Sign/Verify (AddressDetails.qml:299-320): below the content ---
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface

            // side by side when both labels fit, else one above the other (narrow screens, long translations)
            GridLayout {
                id: actions
                readonly property int margin: m3.screenMargin(root.width)
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                columns: !Daemon.currentWallet.canSignMessage
                    || 2 * Math.max(freezeButton.implicitWidth, signButton.implicitWidth) + columnSpacing <= width ? 2 : 1
                rowSpacing: m3.space8
                columnSpacing: m3.space8

                M3Button {
                    id: freezeButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'tonal'
                    size: 56
                    text: addressdetails.isFrozen
                        ? qsTranslate('AddressDetails', 'Unfreeze address')
                        : qsTranslate('AddressDetails', 'Freeze address')
                    icon.source: Qt.resolvedUrl('../../icons/m3/ac_unit.png')
                    onClicked: addressdetails.freeze(!addressdetails.isFrozen)
                }
                M3Button {
                    id: signButton
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    visible: Daemon.currentWallet.canSignMessage
                    variant: 'tonal'
                    size: 56
                    text: qsTranslate('AddressDetails', 'Sign/Verify')
                    icon.source: Qt.resolvedUrl('../../icons/m3/draw.png')
                    onClicked: {
                        var dialog = app.signVerifyMessageDialog.createObject(app, {
                            address: root.address
                        })
                        dialog.open()
                    }
                }
            }
        }
    }

    // AddressDetails.qml:111-114
    function showHistory() {
        app.pushPage(app.routes.addressHistory, {
            address: root.address,
            backingModel: addressdetails.historyModel
        })
    }

    // --- Delete (AddressDetails.qml:321-341): the overflow menu of the top app bar ---
    M3Menu {
        id: overflowMenu
        x: app.width - overflowMenu.width - m3.space8
        y: app.header ? app.header.height - m3.space8 : 0

        MenuItem {
            text: qsTranslate('AddressDetails', 'Delete')
            icon.source: Qt.resolvedUrl('../../icons/m3/delete.png')
            onTriggered: root.deleteAddress()
        }
    }

    AddressDetails {
        id: addressdetails
        wallet: Daemon.currentWallet
        address: root.address
        onFrozenChanged: addressDetailsChanged()
        onLabelChanged: addressDetailsChanged()
        onAuthRequired: (method, authMessage) => {
            app.handleAuthRequired(addressdetails, method, authMessage)
        }
        onAddressDeleteFailed: (message) => {
            var dialog = app.messageDialog.createObject(root, {
                text: message
            })
            dialog.open()
        }
    }

    Binding {
        target: AppController
        property: 'secureWindow'
        when: root.visible  // enables stacking multiple secureWindow dialogs
        value: Boolean(addressdetails.privkey)
    }
}
