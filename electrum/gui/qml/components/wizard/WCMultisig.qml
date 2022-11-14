import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.1

import org.electrum 1.0

import "../controls"

WizardComponent {
    id: root

    valid: true

    property int participants: 2
    property int signatures: 2

    onParticipantsChanged: {
        if (participants < signatures)
            signatures = participants
        piechart.updateSlices()
    }
    onSignaturesChanged: {
        piechart.updateSlices()
    }

    function apply() {
        wizard_data['multisig_participants'] = participants
        wizard_data['multisig_signatures'] = signatures
        wizard_data['multisig_cosigner_data'] = {}
    }

    Flickable {
        anchors.fill: parent
        contentHeight: rootLayout.height
        clip:true
        interactive: height < contentHeight

        ColumnLayout {
            id: rootLayout
            width: parent.width

            Label { text: qsTr('Multisig wallet') }

            InfoTextArea {
                Layout.preferredWidth: parent.width
                text: qsTr('Choose the number of participants, and the number of signatures needed to unlock funds in your wallet.')
            }

            Piechart {
                id: piechart
                Layout.preferredWidth: parent.width * 1/2
                Layout.alignment: Qt.AlignHCenter
                Layout.preferredHeight: 200 // TODO
                showLegend: false
                innerOffset: 3
                function updateSlices() {
                    var s = []
                    for (let i=0; i < participants; i++) {
                        var item = {
                            v: (1/participants),
                            color: i < signatures ? constants.colorPiechartSignature : constants.colorPiechartParticipant
                        }
                        s.push(item)
                    }
                    piechart.slices = s
                }
            }

            Label {
                text: qsTr('Number of cosigners: %1').arg(participants)
            }

            Slider {
                id: participants_slider
                Layout.preferredWidth: parent.width * 4/5
                Layout.alignment: Qt.AlignHCenter
                snapMode: Slider.SnapAlways
                stepSize: 1
                from: 2
                to: 15
                onValueChanged: {
                    if (activeFocus)
                        participants = value
                }
            }

            Label {
                text: qsTr('Number of signatures: %1').arg(signatures)
            }

            Slider {
                id: signatures_slider
                Layout.preferredWidth: parent.width * 4/5
                Layout.alignment: Qt.AlignHCenter
                snapMode: Slider.SnapAlways
                stepSize: 1
                from: 1
                to: participants
                value: signatures
                onValueChanged: {
                    if (activeFocus)
                        signatures = value
                }
            }
        }
    }

    Component.onCompleted: piechart.updateSlices()

}
