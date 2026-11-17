import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

// Material 3 page: the new seed, to be written down.
// repeats: components/wizard/WCCreateSeed.qml:9-90 @ e6df7e1c8 (securePage, valid, apply(), setWarningText(),
// Bitcoin.generateSeed(wizard_data['seed_type']) and onGeneratedSeedChanged, the busy indicator while there is no
// seed, no copy action). The seed is a numbered grid of words (M3SeedWords, owner fork R-O4 a).
WizardComponent {
    securePage: true

    valid: seedtext.text != ''

    function apply() {
        wizard_data['seed'] = seedtext.text
        wizard_data['seed_variant'] = 'electrum' // generated seed always electrum variant
        wizard_data['seed_extend'] = true  // true so we get forwarded to the passphrase page
    }

    function setWarningText(numwords) {
        var t = [
            '<p>',
            qsTranslate('WCCreateSeed', 'Please save these %1 words on paper (order is important).').arg(numwords),
            qsTranslate('WCCreateSeed', 'This seed will allow you to recover your wallet in case of computer failure.'),
            '</p>',
            '<b>' + qsTranslate('WCCreateSeed', 'WARNING') + ':</b>',
            '<ul>',
            '<li>' + qsTranslate('WCCreateSeed', 'Never disclose your seed.') + '</li>',
            '<li>' + qsTranslate('WCCreateSeed', 'Never type it on a website.') + '</li>',
            '<li>' + qsTranslate('WCCreateSeed', 'Do not store it electronically.') + '</li>',
            '</ul>'
        ]
        warningtext.text = t.join(' ')
    }

    Flickable {
        anchors.fill: parent
        contentHeight: mainLayout.height + m3.space16
        clip:true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: mainLayout
            width: parent.width
            spacing: m3.space16

            M3InfoText {
                id: warningtext
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                tone: 'warn'
                textFormat: Text.RichText
            }

            M3Text {
                Layout.fillWidth: true
                role: 'titleMedium'
                wrapMode: Text.Wrap
                text: qsTranslate('WCCreateSeed', 'Your wallet generation seed is:')
            }

            M3SeedWords {
                id: seedtext
                Layout.fillWidth: true
                Layout.minimumHeight: 120

                BusyIndicator {
                    anchors.centerIn: parent
                    visible: seedtext.text == ''
                    running: visible
                }
            }

            Component.onCompleted : {
                setWarningText(12)
            }
        }
    }

    Component.onCompleted: {
        bitcoin.generateSeed(wizard_data['seed_type'])
    }

    Bitcoin {
        id: bitcoin
        onGeneratedSeedChanged: {
            seedtext.text = generatedSeed
            setWarningText(generatedSeed.split(' ').length)
        }
    }
}
