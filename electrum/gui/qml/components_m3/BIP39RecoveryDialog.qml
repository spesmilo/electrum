import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// "Detect BIP39 accounts" of the Material 3 GUI, opened over the wizard by wizard/WCScriptAndDerivation.qml
// ("Detect Existing Accounts"; found there by `import ".."`, as the classic page finds the classic dialog).
// repeats: components/BIP39RecoveryDialog.qml:10-157 (the properties seed, seedExtraWords,
// walletType, derivationPath, scriptType; z: 1 so that it covers the wizard; 4/5 of the height; the text and the
// icon style of the notice by the state of the model; the list of the model: description, script type,
// derivation path, a tap takes the derivation path and the script type of the row and accepts; the model and
// startScan(walletType, seed, seedExtraWords) on completion).
// Look: an M3Dialog, the notice as M3InfoText (the same IconStyle values: spinner,
// info, error), the list in a surfaceContainerLow container with M3ListItem rows (account_balance_wallet icon,
// the description wrapping, "script type: ..." and "derivation path: ..." as the second line), a text button
// "Cancel" (doReject(), the same as the Android back button and the tap outside).
// Strings carried over keep the translation context of BIP39RecoveryDialog.qml.
M3Dialog {
    id: dialog
    title: qsTranslate('BIP39RecoveryDialog', 'Detect BIP39 accounts')

    property string seed
    property string seedExtraWords
    property string walletType

    property string derivationPath
    property string scriptType

    z: 1 // raise z so it also covers wizard dialog

    height: parent.height * 4/5

    contentItem: ColumnLayout {
        id: rootLayout
        spacing: m3.space16

        M3InfoText {
            Layout.fillWidth: true
            compact: true

            text: bip39RecoveryListModel.state == Bip39RecoveryListModel.Scanning
                ? qsTranslate('BIP39RecoveryDialog', 'Scanning for accounts...')
                : bip39RecoveryListModel.state == Bip39RecoveryListModel.Success
                    ? listview.count > 0
                        ? qsTranslate('BIP39RecoveryDialog', 'Choose an account to restore.')
                        : qsTranslate('BIP39RecoveryDialog', 'No existing accounts found.')
                    : bip39RecoveryListModel.state == Bip39RecoveryListModel.Failed
                        ? qsTranslate('BIP39RecoveryDialog', 'Recovery failed')
                        : qsTranslate('BIP39RecoveryDialog', 'Recovery cancelled')
            iconStyle: bip39RecoveryListModel.state == Bip39RecoveryListModel.Scanning
                ? M3InfoText.IconStyle.Spinner
                : bip39RecoveryListModel.state == Bip39RecoveryListModel.Success
                    ? M3InfoText.IconStyle.Info
                    : M3InfoText.IconStyle.Error
        }

        Rectangle {
            id: accountsFrame
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: m3.surfaceContainerLow
            radius: m3.radiusL
            clip: true

            ListView {
                id: listview
                anchors.fill: parent
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                model: bip39RecoveryListModel

                delegate: M3ListItem {
                    width: ListView.view.width
                    leadingIcon: Qt.resolvedUrl('../../icons/m3/account_balance_wallet.png')
                    headline: model.description
                    headlineMaxLines: 3
                    supporting: qsTranslate('BIP39RecoveryDialog', 'script type') + ': ' + model.script_type
                        + '\n' + qsTranslate('BIP39RecoveryDialog', 'derivation path') + ': ' + model.derivation_path
                    supportingMaxLines: 4

                    onClicked: {
                        dialog.derivationPath = model.derivation_path
                        dialog.scriptType = model.script_type
                        dialog.doAccept()
                    }
                }

                ScrollIndicator.vertical: ScrollIndicator { }
            }
        }
    }

    buttons: [
        M3Button {
            variant: 'text'
            text: qsTranslate('Wizard', 'Cancel')
            onClicked: dialog.doReject()
        }
    ]

    Bip39RecoveryListModel {
        id: bip39RecoveryListModel
    }

    Component.onCompleted: {
        bip39RecoveryListModel.startScan(walletType, seed, seedExtraWords)
    }
}
