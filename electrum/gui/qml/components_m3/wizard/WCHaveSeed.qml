import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "../controls"

// Material 3 page: restore from an existing seed (also the seed of a multisig cosigner and of a 2FA wallet), with
// the seed keyboard pinned to the bottom.
// repeats: components/wizard/WCHaveSeed.qml:10-248 (securePage, valid, is2fa, cosigner, participants,
// multisigMasterPubkey, apply(), setSeedTypeHelpText(), checkValid() with wiz.verifySeed and the multisig checks,
// the indicator text and validity, startValidationTimer() and the 500 ms timer with checkValid() + checkIsLast(),
// the seed type choice and the order of its handler (help text, checkIsLast, checkValid), Component.onCompleted).
// The combo box seed_variant_cb is a segmented button; its value is kept in seedVariant. The help text of the
// seed type keeps the classic `infotext` (text, visible) set by setSeedTypeHelpText(); on a low page it is one
// line that opens on a tap.
// Added (view only, `valid` and the check do not change): with the Electrum type chosen and 12 or more words that
// Electrum does not recognize but that are a BIP39 seed, a line below the field suggests BIP39
// (_updateSuggestBip39); the field with its indicator and that line is scrolled into view on every
// change of the text and again once the indicator or the line shows up.
WizardComponent {
    id: root
    securePage: true

    valid: false

    property bool is2fa: false
    property int cosigner: 0
    property int participants: 0
    property string multisigMasterPubkey: wizard_data['multisig_master_pubkey']

    property string _seedType
    property string _validationMessage
    property bool _canPassphrase
    property bool _seedValid

    property string seedVariant: 'electrum'

    // the combo box of the classic page
    readonly property QtObject seed_variant_cb: QtObject {
        readonly property string currentValue: root.seedVariant
    }

    // the help text of the classic page, set by setSeedTypeHelpText()
    QtObject {
        id: infotext
        property string text
        property bool visible: false
    }

    function apply() {
        if (cosigner) {
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed'] = seedtext.text
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_variant'] = seed_variant_cb.currentValue
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_type'] = _seedType
            wizard_data['multisig_cosigner_data'][cosigner.toString()]['seed_extend'] = _canPassphrase
        } else {
            wizard_data['seed'] = seedtext.text
            wizard_data['seed_variant'] = seed_variant_cb.currentValue
            wizard_data['seed_type'] = _seedType
            wizard_data['seed_extend'] = _canPassphrase

            // determine script type from electrum seed type
            // (used to limit script type options for bip39 cosigners)
            if (wizard_data['wallet_type'] == 'multisig' && seed_variant_cb.currentValue == 'electrum') {
                wizard_data['script_type'] = {
                    'standard': 'p2sh',
                    'segwit': 'p2wsh'
                }[_seedType]
            }
        }
    }

    function setSeedTypeHelpText() {
        var t = {
            'electrum': [
                // not shown as electrum is the default seed type anyways and the name is self-explanatory
                qsTranslate('WCHaveSeed', 'Electrum seeds are the default seed type.'),
                qsTranslate('WCHaveSeed', 'If you are restoring from a seed previously created by Electrum, choose this option')
            ].join(' '),
            'bip39': [
                qsTranslate('WCHaveSeed', 'BIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
                qsTranslate('WCHaveSeed', 'BIP39 seeds do not include a version number, which compromises compatibility with future software.'),
            ].join(' '),
            'slip39': [
                qsTranslate('WCHaveSeed', 'SLIP39 seeds can be imported in Electrum, so that users can access funds locked in other wallets.'),
            ].join(' ')
        }
        infotext.text = t[seed_variant_cb.currentValue]
        infotext.visible = !cosigner && !is2fa && seed_variant_cb.currentValue != 'electrum'
    }

    function checkValid() {
        valid = false
        _seedValid = false

        var verifyResult = wiz.verifySeed(seedtext.text, seed_variant_cb.currentValue, wizard_data['wallet_type'])

        _validationMessage = verifyResult.message
        _seedType = verifyResult.type
        _canPassphrase = verifyResult.can_passphrase

        if (!cosigner || !verifyResult.valid) {
            _seedValid = verifyResult.valid
        } else {
            // bip39 validate after derivation path is known
            if (seed_variant_cb.currentValue == 'electrum') {
                apply()
                if (wiz.hasDuplicateMasterKeys(wizard_data)) {
                    _validationMessage = qsTranslate('WCHaveSeed', 'Error: duplicate master public key')
                    return
                } else if (wiz.hasHeterogeneousMasterKeys(wizard_data)) {
                    _validationMessage = qsTranslate('WCHaveSeed', 'Error: master public key types do not match')
                    return
                } else {
                    _seedValid = true
                }
            } else {
                _seedValid = true
            }
        }

        valid = _seedValid
    }

    // M3: the hint to choose BIP39 (view only). Shown when the Electrum type is chosen, there are 12 or more words,
    // Electrum does not recognize them as a seed of any type (no _seedType: a recognized seed of another type, e.g.
    // a duplicate cosigner key, gets no hint) and the same words pass the BIP39 check of this page, the call that
    // checkValid() makes when BIP39 is chosen: wiz.verifySeed(text, 'bip39', wallet_type) with no message, i.e. a
    // known wordlist and a good checksum (a BIP39 seed is "valid" even with a failed checksum, wizard.py
    // validate_seed). An Electrum seed with a mistyped word gets no hint, unless those words happen to be a BIP39
    // seed too (1 in 16 for 12 random words, the 4-bit checksum). Recomputed after each check, cleared on typing.
    property bool _suggestBip39: false
    function _updateSuggestBip39() {
        _suggestBip39 = false
        if (is2fa || seed_variant_cb.currentValue != 'electrum' || _seedType !== '')
            return
        if (seedtext.text.split(/\s+/).filter(function(w) { return w !== '' }).length < 12)
            return
        var bip39 = wiz.verifySeed(seedtext.text, 'bip39', wizard_data['wallet_type'])
        _suggestBip39 = bip39.valid && bip39.message === ''
    }

    // M3: a low page shows the help text as one line until tapped
    readonly property bool _lowPage: flick.height < 400
    property bool _helpOpen: false

    Flickable {
        id: flick
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: keyboard.top
        contentHeight: mainLayout.height + m3.space16
        clip:true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        onHeightChanged: root.ensureVisible(flick, seedBlock)

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            CosignerHeader {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                pubkey: multisigMasterPubkey
                cosigner: root.cosigner
                participants: root.participants
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                visible: !is2fa
                spacing: m3.space16

                M3Text {
                    role: 'titleSmall'
                    text: qsTranslate('WCHaveSeed', 'Seed Type')
                }

                M3SegmentedButton {
                    Layout.fillWidth: true
                    Layout.maximumWidth: 320
                    model: [
                        { text: 'Electrum', value: 'electrum' },
                        { text: 'BIP39', value: 'bip39' }
                    ]
                    currentValue: root.seedVariant
                    onActivated: (value) => {
                        root.seedVariant = value
                        setSeedTypeHelpText()
                        checkIsLast()
                        checkValid()
                        root._updateSuggestBip39()  // M3
                    }
                }
            }

            M3InfoText {
                Layout.fillWidth: true
                visible: infotext.visible && (!root._lowPage || root._helpOpen)
                compact: true
                text: infotext.text
            }

            // the help text in one line on a low page; a tap shows all of it
            M3Card {
                Layout.fillWidth: true
                visible: infotext.visible && root._lowPage && !root._helpOpen
                color: m3.secondaryContainer
                radius: m3.radiusM
                padding: m3.space8
                leftPadding: m3.space12
                clickable: true
                onClicked: root._helpOpen = true

                RowLayout {
                    width: parent.width
                    spacing: m3.space8
                    M3Icon {
                        size: 20
                        source: Qt.resolvedUrl('../../../icons/m3/info.png')
                        color: m3.secondaryContainerOn
                    }
                    M3Text {
                        Layout.fillWidth: true
                        role: 'bodyMedium'
                        color: m3.secondaryContainerOn
                        elide: Text.ElideRight
                        text: infotext.text
                    }
                    M3Icon {
                        size: 20
                        source: Qt.resolvedUrl('../../../icons/m3/expand_more.png')
                        color: m3.secondaryContainerOn
                    }
                }
            }

            ColumnLayout {
                id: seedBlock
                Layout.fillWidth: true
                spacing: m3.space8

                // the indicator or the BIP39 line showed up (after the check): scroll them into view as well
                onHeightChanged: Qt.callLater(root.ensureVisible, flick, seedBlock)

                M3SeedField {
                    id: seedtext
                    Layout.fillWidth: true

                    placeholderText: cosigner ? qsTranslate('WCHaveSeed', 'Enter cosigner seed') : qsTranslate('WCHaveSeed', 'Enter your seed')

                    indicatorValid: root._seedValid
                        ? root._seedType == 'bip39' && root._validationMessage
                            ? false
                            : root._seedValid
                        : root._seedValid
                    indicatorText: root._validationMessage
                            ? root._validationMessage
                            : root._seedType
                    onTextChanged: {
                        startValidationTimer()
                        root._suggestBip39 = false  // M3
                        Qt.callLater(root.ensureVisible, flick, seedBlock)
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: m3.space16
                    Layout.rightMargin: m3.space16
                    visible: root._suggestBip39
                    spacing: m3.space8

                    M3Icon {
                        Layout.alignment: Qt.AlignTop
                        size: 18
                        source: Qt.resolvedUrl('../../../icons/m3/info.png')
                        color: m3.tertiary
                    }
                    M3Text {
                        Layout.fillWidth: true
                        role: 'bodyMedium'
                        color: m3.tertiary
                        wrapMode: Text.Wrap
                        lineHeightMode: Text.ProportionalHeight
                        lineHeight: 1.0
                        text: qsTr('Not an Electrum seed. If it comes from another wallet, choose BIP39.')
                    }
                }
            }
        }
    }

    M3SeedKeyboard {
        id: keyboard
        anchors.bottom: parent.bottom
        x: -root.leftPadding
        width: root.width
        target: seedtext
        keyHeight: wizard.height < 640 ? 40 : 48
    }

    function startValidationTimer() {
        valid = false
        root._seedType = ''
        root._validationMessage = ''
        validationTimer.restart()
    }

    Timer {
        id: validationTimer
        interval: 500
        repeat: false
        onTriggered: {
            checkValid()
            // checkIsLast depends on 'seed_extend'(_canPassphrase) getting set in apply()
            checkIsLast()
            root._updateSuggestBip39()  // M3
        }
    }

    Component.onCompleted: {
        if (wizard_data['wallet_type'] == '2fa') {
            is2fa = true
        } else if (wizard_data['wallet_type'] == 'multisig') {
            participants = wizard_data['multisig_participants']
            if ('multisig_current_cosigner' in wizard_data)
                cosigner = wizard_data['multisig_current_cosigner']
        }
        setSeedTypeHelpText()
        Qt.callLater(seedtext.forceActiveFocus)
    }

}
