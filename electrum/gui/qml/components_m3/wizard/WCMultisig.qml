import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

import org.electrum 1.0

import "../controls"

// Material 3 page: the number of cosigners and of signatures of a multisig wallet.
// repeats: components/wizard/WCMultisig.qml:9-108 @ e6df7e1c8 (valid, participants 2 and signatures 2 at start; a
// lower number of participants cuts the signatures; apply(); the explanation; "Number of cosigners: %1" 2...15 and
// "Number of signatures: %1" 1...participants, both changed by the user only (classic: `if (activeFocus)`, here
// M3SliderRow.moved, emitted on user action only)).
// Look (DESIGN-M2-onboarding.md 3.1, R-O13): the explanation as M3InfoText; instead of the classic Canvas pie in the
// colors of `constants`, a row of 16 dp circles "N of M": one per cosigner, the signatures filled in m3.primary, the
// others outlined in m3.outline; the two numbers as M3SliderRow. The circles are bindings of participants and
// signatures (the classic piechart.updateSlices() on every change is not needed).
// Strings carried over keep the translation context of WCMultisig.qml.
WizardComponent {
    id: root

    valid: true

    property int participants: 2
    property int signatures: 2

    onParticipantsChanged: {
        if (participants < signatures)
            signatures = participants
    }

    function apply() {
        wizard_data['multisig_participants'] = participants
        wizard_data['multisig_signatures'] = signatures
        wizard_data['multisig_cosigner_data'] = {}
    }

    Flickable {
        anchors.fill: parent
        contentHeight: rootLayout.height + m3.space16
        clip: true
        interactive: height < contentHeight
        boundsBehavior: Flickable.StopAtBounds

        ColumnLayout {
            id: rootLayout
            width: parent.width
            spacing: m3.space16

            M3InfoText {
                Layout.fillWidth: true
                Layout.topMargin: m3.space8
                compact: true
                text: qsTranslate('WCMultisig', 'Choose the number of participants, and the number of signatures needed to unlock funds in your wallet.')
            }

            // "N of M": one circle per cosigner, the signatures needed filled
            Flow {
                id: circles
                readonly property int circle: 16
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: m3.space8
                Layout.bottomMargin: m3.space8
                Layout.preferredWidth: Math.min(rootLayout.width, participants * (circle + spacing) - spacing)
                spacing: m3.space8

                Repeater {
                    model: participants
                    delegate: Rectangle {
                        required property int index
                        width: circles.circle
                        height: circles.circle
                        radius: width / 2
                        color: index < signatures ? m3.primary : 'transparent'
                        border.width: index < signatures ? 0 : 2
                        border.color: m3.outline
                    }
                }
            }

            M3ListGroup {
                Layout.fillWidth: true

                M3SliderRow {
                    headline: qsTranslate('WCMultisig', 'Number of cosigners: %1').arg(participants)
                    snapMode: Slider.SnapAlways
                    stepSize: 1
                    from: 2
                    to: 15
                    value: participants
                    onMoved: (value) => {
                        participants = value
                    }
                }

                M3SliderRow {
                    headline: qsTranslate('WCMultisig', 'Number of signatures: %1').arg(signatures)
                    snapMode: Slider.SnapAlways
                    stepSize: 1
                    from: 1
                    to: participants
                    value: signatures
                    onMoved: (value) => {
                        signatures = value
                    }
                }
            }
        }
    }

}
