import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

// Lightning payment details of the Material 3 GUI (route app.routes.lightningPaymentDetails, replaces the classic
// LightningPaymentDetails).
// repeats: components/LightningPaymentDetails.qml:10-348 @ e6df7e1c8: the page contract (key), the "Paid" notice,
// date, amount received / sent, the fee of a sent payment, label and its editing, payment hash and preimage
// with their share dialogs, the LnPaymentDetails object. Only the look differs; the details are M3DetailRow rows
// (M2-MAP F-4). The classic page has no description row (the label is the description), so neither has this one.
// Strings keep the translation context of the classic file (qsTranslate('LightningPaymentDetails', ...)).
M3Page {
    id: root

    property string key

    title: qsTranslate('LightningPaymentDetails', 'Lightning payment details')

    Flickable {
        id: flickable
        anchors.fill: parent
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

            // --- "Paid" (LightningPaymentDetails.qml:163-170) ---
            M3InfoText {
                Layout.fillWidth: true
                visible: text
                text: lnpaymentdetails.status ? qsTranslate('LightningPaymentDetails', 'Paid') : ''
                iconStyle: M3InfoText.IconStyle.Done
            }

            // --- amount (LightningPaymentDetails.qml:181-191) ---
            ColumnLayout {
                Layout.fillWidth: true
                spacing: m3.space8

                Rectangle {
                    Layout.alignment: Qt.AlignHCenter
                    implicitWidth: 56
                    implicitHeight: 56
                    radius: 28
                    color: m3.tertiaryContainer
                    M3Icon {
                        anchors.centerIn: parent
                        source: Qt.resolvedUrl('../../icons/m3/bolt.png')
                        color: m3.tertiaryContainerOn
                    }
                }

                M3Text {
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignHCenter
                    role: 'labelLarge'
                    color: m3.surfaceVariantOn
                    wrapMode: Text.Wrap
                    text: lnpaymentdetails.amount.msatsInt > 0
                            ? qsTranslate('LightningPaymentDetails', 'Amount received')
                            : qsTranslate('LightningPaymentDetails', 'Amount sent')
                }

                M3Amount {
                    Layout.alignment: Qt.AlignHCenter
                    amount: lnpaymentdetails.amount
                    timestamp: lnpaymentdetails.timestamp
                    role: 'headlineSmall'
                    unitRole: 'titleMedium'
                    fiatRole: 'bodyMedium'
                }
            }

            // --- details (LightningPaymentDetails.qml:172-262) ---
            M3ListGroup {
                Layout.fillWidth: true

                M3DetailRow {
                    label: qsTranslate('LightningPaymentDetails', 'Date')
                    text: lnpaymentdetails.date
                }

                TxAmountRow {
                    visible: lnpaymentdetails.amount.msatsInt < 0
                    label: qsTranslate('LightningPaymentDetails', 'Transaction fee')
                    amount: lnpaymentdetails.fee
                    timestamp: lnpaymentdetails.timestamp
                }

                // --- label (LightningPaymentDetails.qml:205-262) ---
                M3DetailRow {
                    visible: !labelEditRow.editmode
                    label: qsTranslate('LightningPaymentDetails', 'Label')
                    text: lnpaymentdetails.label
                    actions: [
                        M3IconButton {
                            tooltip: qsTr('Edit')
                            icon.source: Qt.resolvedUrl('../../icons/m3/edit.png')
                            onClicked: {
                                labelEdit.text = lnpaymentdetails.label
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
                            label: qsTranslate('LightningPaymentDetails', 'Label')
                            text: lnpaymentdetails.label
                        }
                        M3IconButton {
                            tooltip: qsTr('Save')
                            icon.source: Qt.resolvedUrl('../../icons/m3/check.png')
                            icon.color: m3.primary
                            onClicked: {
                                labelEditRow.editmode = false
                                lnpaymentdetails.setLabel(labelEdit.text)
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

            // --- technical properties (LightningPaymentDetails.qml:264-337) ---
            M3SectionHeader {
                Layout.fillWidth: true
                Layout.bottomMargin: -m3.space8
                leftPadding: 0
                visible: lnpaymentdetails.paymentHash || lnpaymentdetails.preimage
                text: qsTranslate('LightningPaymentDetails', 'Technical properties')
            }

            M3ListGroup {
                Layout.fillWidth: true
                visible: lnpaymentdetails.paymentHash || lnpaymentdetails.preimage

                M3DetailRow {
                    visible: lnpaymentdetails.paymentHash
                    label: qsTranslate('LightningPaymentDetails', 'Payment hash')
                    text: lnpaymentdetails.paymentHash
                    monospace: true
                    shareable: true
                    shareTitle: qsTranslate('LightningPaymentDetails', 'Payment hash')
                }

                M3DetailRow {
                    visible: lnpaymentdetails.preimage
                    label: qsTranslate('LightningPaymentDetails', 'Preimage')
                    text: lnpaymentdetails.preimage
                    monospace: true
                    shareable: true
                    shareTitle: qsTranslate('LightningPaymentDetails', 'Preimage')
                }
            }
        }
    }

    LnPaymentDetails {
        id: lnpaymentdetails
        wallet: Daemon.currentWallet
        key: root.key
    }
}
