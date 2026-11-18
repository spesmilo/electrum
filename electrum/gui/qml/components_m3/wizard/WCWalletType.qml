import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import "../controls"

// Material 3 page: kind of the new wallet.
// repeats: components/wizard/WCWalletType.qml:7-60 (valid, apply() with the seed type by the wallet
// type, the ButtonGroup and the `wallettype` of every option, the first option checked, the strings).
// The icons are neutral (no "safe" shield on the paid two-factor service).
WizardComponent {
    valid: wallettypegroup.checkedButton !== null

    function apply() {
        // apply gets called when the page is rendered and implicitly
        // sets the first radio button or the last selected one when going back
        wizard_data['wallet_type'] = wallettypegroup.checkedButton.wallettype
        delete wizard_data['seed_type']
        if (wizard_data['wallet_type'] == 'standard')
            wizard_data['seed_type'] = 'segwit'
        else if (wizard_data['wallet_type'] == '2fa')
            wizard_data['seed_type'] = '2fa_segwit'
        else if (wizard_data['wallet_type'] == 'multisig')
            wizard_data['seed_type'] = 'segwit'
    }

    ButtonGroup {
        id: wallettypegroup
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3Text {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('WCWalletType', 'What kind of wallet do you want to create?')
            }

            M3ListGroup {
                Layout.fillWidth: true
                M3RadioRow {
                    ButtonGroup.group: wallettypegroup
                    property string wallettype: 'standard'
                    checked: true
                    leadingIcon: Qt.resolvedUrl('../../../icons/m3/account_balance_wallet.png')
                    text: qsTranslate('WCWalletType', 'Standard Wallet')
                }
                M3RadioRow {
                    ButtonGroup.group: wallettypegroup
                    property string wallettype: '2fa'
                    leadingIcon: Qt.resolvedUrl('../../../icons/m3/key.png')
                    text: qsTranslate('WCWalletType', 'Wallet with two-factor authentication')
                }
                M3RadioRow {
                    ButtonGroup.group: wallettypegroup
                    property string wallettype: 'multisig'
                    leadingIcon: Qt.resolvedUrl('../../../icons/m3/group.png')
                    text: qsTranslate('WCWalletType', 'Multi-signature wallet')
                }
                M3RadioRow {
                    ButtonGroup.group: wallettypegroup
                    property string wallettype: 'imported'
                    leadingIcon: Qt.resolvedUrl('../../../icons/m3/list.png')
                    text: qsTranslate('WCWalletType', 'Import Bitcoin addresses or private keys')
                }
            }
        }
    }
}
