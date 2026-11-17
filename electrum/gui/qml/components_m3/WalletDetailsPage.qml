import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "controls"

// Wallet details of the Material 3 GUI (route app.routes.walletDetails, from the overflow menu; replaces the classic
// WalletDetails).
// repeats: components/WalletDetails.qml:10-684 @ e6df7e1c8: the tags of the wallet (type, script type, HD, watch
// only, encrypted, hardware, Lightning, seed) and their conditions; the name and its editing
// (Daemon.isValidWalletName, Daemon.renameWallet); the seed, shown only after Daemon.currentWallet.requestShowSeed()
// (the wallet asks for authentication; seedRetrieved shows it, a tap hides it again) and the seed extension while
// the seed is shown; the Lightning node ID and its share dialog; 2FA: state, remaining transactions, billing
// (Config.trustedcoinPrepay from the billing model of the trustedcoin plugin); the keystores (type, imported
// addresses or keys, derivation prefix, BIP32 fingerprint, master public key and its share dialog); the actions and
// their conditions: Delete Wallet... (Daemon.checkThenDeleteWallet), Change Password (Daemon.startChangePassword),
// Add addresses / Add keys (imported wallets: ImportAddressesKeysDialog declared on this page), Enable Lightning
// (with its question); the handlers of Daemon (wallet loaded, new unified password, delete errors with their
// confirmations, rename error), of the wallet (new wallet password with the single-password rule, seed retrieved)
// and of Biometrics; the secure window while the seed is shown. Only the look differs.
// Layout (M2-MAP F-3, F-4): tags are chips; details are M3DetailRow rows; the seed is the numbered grid M3SeedWords;
// Change Password, Add addresses / keys and Enable Lightning are buttons below the content; Delete Wallet... (rare
// and destructive) is in the overflow menu of the top app bar (`m3Actions`).
// Strings keep the translation context of the classic file (qsTranslate('WalletDetails', ...)).
M3Page {
    id: rootItem
    objectName: 'WalletDetails'

    title: qsTranslate('WalletDetails', 'Wallet details')

    property bool _is2fa: Daemon.currentWallet && Daemon.currentWallet.walletType == '2fa'
    // the seed is shown (WalletDetails.qml:205-231: seedText.visible)
    property bool _seedShown: false

    // WalletDetails.qml:483-492 (Delete Wallet...): the overflow menu of the top app bar
    property list<Item> m3Actions: [
        M3IconButton {
            tooltip: qsTr('More options')
            icon.source: Qt.resolvedUrl('../../icons/m3/more_vert.png')
            onClicked: overflowMenu.open()
        }
    ]

    // WalletDetails.qml:18-27
    function enableLightning() {
        var dialog = app.messageDialog.createObject(rootItem, {
            title: qsTranslate('WalletDetails', 'Enable Lightning for this wallet?'),
            yesno: true
        })
        dialog.accepted.connect(function() {
            Daemon.currentWallet.enableLightning()
        })
        dialog.open()
    }

    // WalletDetails.qml:29-32
    function importAddressesKeys() {
        var dialog = importAddressesKeysDialog.createObject(rootItem)
        dialog.open()
    }

    // a tag of the wallet (classic Tag): a chip that does nothing on a tap
    component WalletTag: M3Chip {
        focusPolicy: Qt.NoFocus
        hoverEnabled: false
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
                readonly property int margin: m3.screenMargin(rootItem.width)
                x: Math.max(margin, (flickable.width - width) / 2)
                y: m3.space16
                width: Math.min(m3.maxContentWidth, flickable.width - 2 * margin)
                spacing: m3.space16

                // --- tags (WalletDetails.qml:60-126) ---
                Flow {
                    Layout.fillWidth: true
                    spacing: m3.space8

                    WalletTag {
                        text: Daemon.currentWallet.walletType
                        iconSource: Qt.resolvedUrl('../../icons/m3/account_balance_wallet.png')
                    }
                    WalletTag {
                        text: Daemon.currentWallet.txinType
                        iconSource: Qt.resolvedUrl('../../icons/m3/account_tree.png')
                    }
                    WalletTag {
                        text: qsTranslate('WalletDetails', 'HD')
                        visible: Daemon.currentWallet.isDeterministic
                        iconSource: Qt.resolvedUrl('../../icons/m3/hub.png')
                    }
                    WalletTag {
                        text: qsTranslate('WalletDetails', 'Watch only')
                        visible: Daemon.currentWallet.isWatchOnly
                        iconSource: Qt.resolvedUrl('../../icons/m3/visibility.png')
                    }
                    WalletTag {
                        text: qsTranslate('WalletDetails', 'Encrypted')
                        visible: Daemon.currentWallet.isEncrypted
                        iconSource: Qt.resolvedUrl('../../icons/m3/lock.png')
                    }
                    WalletTag {
                        text: qsTranslate('WalletDetails', 'HW')
                        visible: Daemon.currentWallet.isHardware
                        iconSource: Qt.resolvedUrl('../../icons/m3/key.png')
                    }
                    WalletTag {
                        text: qsTranslate('WalletDetails', 'Lightning')
                        visible: Daemon.currentWallet.isLightning
                        iconSource: Qt.resolvedUrl('../../icons/m3/bolt.png')
                    }
                    WalletTag {
                        text: qsTranslate('WalletDetails', 'Seed')
                        visible: Daemon.currentWallet.hasSeed
                        iconSource: Qt.resolvedUrl('../../icons/m3/key.png')
                    }
                }

                M3ListGroup {
                    Layout.fillWidth: true
                    visible: Daemon.currentWallet

                    // --- name (WalletDetails.qml:133-188) ---
                    M3DetailRow {
                        visible: !walletNameContent.editmode
                        label: qsTranslate('WalletDetails', 'Name')
                        text: Daemon.currentWallet.name
                        actions: [
                            M3IconButton {
                                tooltip: qsTr('Edit')
                                icon.source: Qt.resolvedUrl('../../icons/m3/edit.png')
                                onClicked: {
                                    walletNameEdit.text = Daemon.currentWallet.name
                                    walletNameContent.editmode = true
                                    walletNameEdit.field.forceActiveFocus()
                                }
                            }
                        ]
                    }

                    Item {
                        id: walletNameContent
                        property bool editmode: false
                        Layout.fillWidth: true
                        visible: editmode
                        implicitHeight: nameEditLayout.implicitHeight + 2 * m3.space8

                        RowLayout {
                            id: nameEditLayout
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.leftMargin: m3.space16
                            anchors.rightMargin: m3.space4
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 0

                            M3TextField {
                                id: walletNameEdit
                                Layout.fillWidth: true
                                label: qsTranslate('WalletDetails', 'Name')
                            }
                            M3IconButton {
                                tooltip: qsTr('Save')
                                icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
                                icon.color: enabled ? m3.primary : m3.surfaceVariantOn
                                enabled: Daemon.isValidWalletName(walletNameEdit.text)
                                onClicked: {
                                    walletNameContent.editmode = false
                                    Daemon.renameWallet(walletNameEdit.text)
                                }
                            }
                            M3IconButton {
                                tooltip: qsTr('Cancel')
                                icon.source: Qt.resolvedUrl('../../icons/m3/close.png')
                                onClicked: walletNameContent.editmode = false
                            }
                        }
                    }

                    // --- Lightning node ID (WalletDetails.qml:257-291) ---
                    M3DetailRow {
                        visible: Daemon.currentWallet.isLightning
                        label: qsTranslate('WalletDetails', 'Lightning Node ID')
                        text: Daemon.currentWallet.lightningNodePubkey
                        monospace: true
                        shareable: true
                        shareTitle: qsTranslate('WalletDetails', 'Lightning Node ID')
                    }

                    // --- 2FA (WalletDetails.qml:293-319) ---
                    M3DetailRow {
                        visible: _is2fa
                        label: qsTranslate('WalletDetails', '2FA')
                        text: Daemon.currentWallet.canSignWithoutServer
                                ? qsTranslate('WalletDetails', 'disabled (can sign without server)')
                                : qsTranslate('WalletDetails', 'enabled')
                    }
                    M3DetailRow {
                        visible: _is2fa && !Daemon.currentWallet.canSignWithoutServer
                        label: qsTranslate('WalletDetails', 'Remaining TX')
                        text: 'tx_remaining' in Daemon.currentWallet.billingInfo
                                ? Daemon.currentWallet.billingInfo['tx_remaining']
                                : qsTranslate('WalletDetails', 'unknown')
                    }
                }

                // --- seed (WalletDetails.qml:190-255) ---
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    visible: Daemon.currentWallet.hasSeed
                    text: qsTranslate('WalletDetails', 'Seed')
                }

                // "Tap to show seed": requestShowSeed(); the wallet asks for authentication, seedRetrieved shows it
                M3ListGroup {
                    Layout.fillWidth: true
                    visible: Daemon.currentWallet.hasSeed && !rootItem._seedShown

                    M3ListItem {
                        leadingIcon: Qt.resolvedUrl('../../icons/m3/visibility.png')
                        headline: qsTranslate('WalletDetails', 'Tap to show seed')
                        onClicked: Daemon.currentWallet.requestShowSeed()
                    }
                }

                // the seed, shown; a tap hides it again (WalletDetails.qml:221-231)
                M3SeedWords {
                    id: seedText
                    Layout.fillWidth: true
                    visible: Daemon.currentWallet.hasSeed && rootItem._seedShown
                    text: rootItem._seedShown ? Daemon.currentWallet.seed : ''

                    MouseArea {
                        anchors.fill: parent
                        onClicked: rootItem._seedShown = false
                    }
                }

                M3ListGroup {
                    Layout.fillWidth: true
                    visible: seedText.visible

                    M3ListItem {
                        leadingIcon: Qt.resolvedUrl('../../icons/m3/visibility_off.png')
                        headline: qsTr('Hide seed')
                        onClicked: rootItem._seedShown = false
                    }

                    // WalletDetails.qml:235-255
                    M3DetailRow {
                        id: seed_extension_label
                        visible: rootItem._seedShown && Daemon.currentWallet.seedPassphrase
                        label: qsTranslate('WalletDetails', 'Seed Extension')
                        text: rootItem._seedShown ? Daemon.currentWallet.seedPassphrase : ''
                        monospace: true
                    }
                }

                // --- 2FA billing (WalletDetails.qml:321-364) ---
                M3SectionHeader {
                    Layout.fillWidth: true
                    Layout.bottomMargin: -m3.space8
                    leftPadding: 0
                    visible: _is2fa && !Daemon.currentWallet.canSignWithoutServer
                    text: qsTranslate('WalletDetails', 'Billing')
                }

                M3ListGroup {
                    Layout.fillWidth: true
                    visible: _is2fa && !Daemon.currentWallet.canSignWithoutServer

                    ButtonGroup {
                        id: billinggroup
                        onCheckedButtonChanged: {
                            Config.trustedcoinPrepay = checkedButton.value
                        }
                    }

                    Repeater {
                        model: _is2fa ? AppController.plugin('trustedcoin').billingModel : []
                        delegate: M3RadioRow {
                            ButtonGroup.group: billinggroup
                            property string value: modelData.value
                            headline: modelData.text
                            supporting: Config.formatSats(modelData.sats_per_tx) + ' ' + Config.baseUnit + '/tx'
                            checked: modelData.value == Config.trustedcoinPrepay
                        }
                    }
                }

                // --- keystores (WalletDetails.qml:366-476) ---
                Repeater {
                    id: keystores
                    model: Daemon.currentWallet.keystores
                    delegate: ColumnLayout {
                        Layout.fillWidth: true
                        spacing: m3.space8

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: m3.space8
                            M3Icon {
                                size: 18
                                color: m3.primary
                                source: modelData.watch_only
                                    ? Qt.resolvedUrl('../../icons/m3/visibility.png')
                                    : Qt.resolvedUrl('../../icons/m3/key.png')
                            }
                            M3Text {
                                Layout.fillWidth: true
                                role: 'titleSmall'
                                color: m3.primary
                                text: qsTranslate('WalletDetails', 'Keystore') + (keystores.count > 1 ? ' #' + index : '')
                            }
                        }

                        M3ListGroup {
                            Layout.fillWidth: true

                            M3DetailRow {
                                visible: modelData.keystore_type
                                label: qsTranslate('WalletDetails', 'Keystore type')
                                text: modelData.keystore_type
                            }
                            M3DetailRow {
                                visible: modelData.num_imported
                                label: modelData.watch_only
                                    ? qsTranslate('WalletDetails', 'Imported addresses')
                                    : qsTranslate('WalletDetails', 'Imported keys')
                                text: modelData.num_imported
                            }
                            M3DetailRow {
                                visible: modelData.derivation_prefix
                                label: qsTranslate('WalletDetails', 'Derivation prefix')
                                text: modelData.derivation_prefix
                                monospace: true
                            }
                            M3DetailRow {
                                visible: modelData.fingerprint
                                label: qsTranslate('WalletDetails', 'BIP32 fingerprint')
                                text: modelData.fingerprint
                                monospace: true
                            }
                            M3DetailRow {
                                visible: modelData.master_pubkey
                                label: qsTranslate('WalletDetails', 'Master Public Key')
                                text: modelData.master_pubkey
                                monospace: true
                                shareable: true
                                shareTitle: qsTranslate('WalletDetails', 'Master Public Key')
                            }
                        }
                    }
                }
            }
        }

        // --- Change Password, Add addresses / keys, Enable Lightning (WalletDetails.qml:493-517): below the content ---
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: actions.implicitHeight + 2 * m3.space16
            color: m3.surface

            GridLayout {
                id: actions
                readonly property int margin: m3.screenMargin(rootItem.width)
                readonly property bool _wide: rootItem.width >= 600
                x: Math.max(margin, (parent.width - width) / 2)
                anchors.verticalCenter: parent.verticalCenter
                width: Math.min(m3.maxContentWidth, parent.width - 2 * margin)
                columns: _wide ? 3 : 1
                rowSpacing: m3.space8
                columnSpacing: m3.space8

                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'filled'
                    size: 56
                    text: qsTranslate('WalletDetails', 'Enable Lightning')
                    onClicked: rootItem.enableLightning()
                    visible: Daemon.currentWallet && Daemon.currentWallet.canHaveLightning && !Daemon.currentWallet.isLightning
                    icon.source: Qt.resolvedUrl('../../icons/m3/bolt.png')
                }
                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'tonal'
                    size: 56
                    visible: Daemon.currentWallet.walletType == 'imported'
                    text: Daemon.currentWallet.isWatchOnly
                            ? qsTranslate('WalletDetails', 'Add addresses')
                            : qsTranslate('WalletDetails', 'Add keys')
                    icon.source: Qt.resolvedUrl('../../icons/m3/add.png')
                    onClicked: rootItem.importAddressesKeys()
                }
                M3Button {
                    Layout.fillWidth: true
                    Layout.preferredWidth: 1
                    variant: 'tonal'
                    size: 56
                    text: qsTranslate('WalletDetails', 'Change Password')
                    onClicked: Daemon.startChangePassword()
                    icon.source: Qt.resolvedUrl('../../icons/m3/lock.png')
                }
            }
        }
    }

    // --- Delete Wallet... (WalletDetails.qml:486-492): the overflow menu of the top app bar ---
    M3Menu {
        id: overflowMenu
        x: app.width - overflowMenu.width - m3.space8
        y: app.header ? app.header.height - m3.space8 : 0

        MenuItem {
            text: qsTranslate('WalletDetails', 'Delete Wallet...')
            icon.source: Qt.resolvedUrl('../../icons/m3/delete.png')
            onTriggered: Daemon.checkThenDeleteWallet(Daemon.currentWallet)
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
                title: qsTranslate('WalletDetails', 'Enter new password'),
                infotext: qsTranslate('WalletDetails', 'If you forget your password, you\'ll need to restore from seed. Please make sure you have your seed stored safely')
            })
            dialog.passwordEntered.connect(function(password) {
                dialog.close()
                var success = Daemon.setPassword(password)
                if (success && Biometrics.isEnabled) {
                    if (Biometrics.isAvailable) {
                        // also update the biometric authentication
                        Biometrics.enable(password)
                    } else {
                        // disable biometric authentication as it is not available
                        Biometrics.disable()
                    }
                }
                var done_dialog = app.messageDialog.createObject(app, {
                    title: success ? qsTranslate('WalletDetails', 'Success') : qsTranslate('WalletDetails', 'Error'),
                    iconSource: success
                        ? ''  // M2-MAP F-5: an info message has no icon
                        : Qt.resolvedUrl('../../icons/m3/warning.png'),
                    text: success ? qsTranslate('WalletDetails', 'Password changed') : qsTranslate('WalletDetails', 'Password change failed')
                })
                done_dialog.open()
            })
            dialog.open()
        }
        function onWalletDeleteError(code, message) {
            if (code == 'unpaid_requests') {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTranslate('WalletDetails', 'Warning'),
                    text: message,
                    yesno: true
                })
                dialog.accepted.connect(function() {
                    Daemon.checkThenDeleteWallet(Daemon.currentWallet, true)
                })
                dialog.open()
            } else if (code == 'balance') {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTranslate('WalletDetails', 'Warning'),
                    text: message,
                    yesno: true
                })
                dialog.accepted.connect(function() {
                    Daemon.checkThenDeleteWallet(Daemon.currentWallet, true, true)
                })
                dialog.open()
            } else {
                var dialog = app.messageDialog.createObject(app, {
                    title: qsTranslate('WalletDetails', 'Error'),
                    iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                    text: message
                })
                dialog.open()
            }
        }
        function onWalletRenameError(message) {
            var dialog = app.messageDialog.createObject(app, {
                title: qsTranslate('WalletDetails', 'Error'),
                iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                text: message
            })
            dialog.open()
        }
    }

    Connections {
        target: Daemon.currentWallet
        function onRequestNewPassword() { // new wallet password
            var dialog = app.passwordDialog.createObject(app, {
                confirmPassword: true,
                title: qsTranslate('WalletDetails', 'Enter new password'),
                infotext: qsTranslate('WalletDetails', 'If you forget your password, you\'ll need to restore from seed. Please make sure you have your seed stored safely')
                        + (Daemon.availableWallets.rowCount() > 1 && Config.walletShouldUseSinglePassword
                        ? "\n\n" + qsTranslate('WalletDetails', 'The new password needs to match the password of any other existing wallet.')
                        : "")
            })
            dialog.passwordEntered.connect(function(password) {
                if (Config.walletShouldUseSinglePassword  // android
                        && Daemon.availableWallets.rowCount() > 1  // has more than one wallet
                        && Daemon.numWalletsWithPassword(password) < 1  // no other wallet uses this new password
                ) {
                    dialog.errorMessage = [
                        qsTranslate('WalletDetails', 'You need to use the password of any other existing wallet.'),
                        qsTranslate('WalletDetails', 'Using different wallet passwords is not supported.'),
                    ].join("\n")
                    dialog.clearPassword()
                    return
                } else {
                    var success = Daemon.currentWallet.setPassword(password)
                    if (success && Config.walletShouldUseSinglePassword) {
                        Daemon.singlePassword = password
                    }
                    var error_msg = qsTranslate('WalletDetails', 'Password change failed')
                }
                dialog.close()
                if (success && Biometrics.isEnabled) {
                    // unlikely to happen as this means the user somehow moved from
                    // a unified password to differing passwords
                    Biometrics.disable()
                }
                var done_dialog = app.messageDialog.createObject(app, {
                    title: success ? qsTranslate('WalletDetails', 'Success') : qsTranslate('WalletDetails', 'Error'),
                    iconSource: success
                        ? ''  // M2-MAP F-5: an info message has no icon
                        : Qt.resolvedUrl('../../icons/m3/warning.png'),
                    text: success ? qsTranslate('WalletDetails', 'Password changed') : error_msg
                })
                done_dialog.open()
            })
            dialog.open()
        }
        function onSeedRetrieved() {
            rootItem._seedShown = true
        }
    }

    Connections {
        target: Biometrics
        function onEnablingFailed(error) {
            if (error === 'CANCELLED') {
                var biometrics_disabled_dialog = app.messageDialog.createObject(app, {
                    title: qsTranslate('WalletDetails', 'Biometric Authentication'),
                    iconSource: Qt.resolvedUrl('../../icons/m3/warning.png'),
                    text: qsTranslate('WalletDetails', 'Biometric authentication disabled. You can enable it again in the settings.')
                })
                biometrics_disabled_dialog.open()
                return
            }
            var err = app.messageDialog.createObject(app, {
                text: qsTranslate('WalletDetails', 'Failed to update biometric authentication to new password: ') + error
            })
            err.open()
        }
    }

    // WalletDetails.qml:668-675
    Component {
        id: importAddressesKeysDialog
        ImportAddressesKeysDialog {
            onClosed: destroy()
        }
    }

    Binding {
        target: AppController
        property: 'secureWindow'
        when: rootItem.visible  // enables stacking multiple secureWindow dialogs
        value: rootItem._seedShown
    }
}
