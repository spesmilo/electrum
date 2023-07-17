import QtQuick
import QtQuick.Layouts
import QtQuick.Controls
import QtQuick.Controls.Material

import org.electrum 1.0

import "controls"

Pane {
    id: root
    width: parent.width
    height: parent.height

    property string key
    property alias label: lnpaymentdetails.label

    signal detailsChanged

    Flickable {
        anchors.fill: parent
        contentHeight: rootLayout.height
        clip: true
        interactive: height < contentHeight

        GridLayout {
            id: rootLayout
            width: parent.width
            columns: 2

            Heading {
                Layout.columnSpan: 2
                text: qsTr('Lightning payment details')
            }

            Label {
                text: qsTr('Status')
                color: Material.accentColor
            }

            Label {
                text: lnpaymentdetails.status
            }

            Label {
                text: qsTr('Date')
                color: Material.accentColor
            }

            Label {
                text: lnpaymentdetails.date
            }

            Label {
                text: lnpaymentdetails.amount.msatsInt > 0
                        ? qsTr('Amount received')
                        : qsTr('Amount sent')
                color: Material.accentColor
            }

            FormattedAmount {
                amount: lnpaymentdetails.amount
                timestamp: lnpaymentdetails.timestamp
            }

            Label {
                visible: lnpaymentdetails.amount.msatsInt < 0
                text: qsTr('Transaction fee')
                color: Material.accentColor
            }

            FormattedAmount {
                visible: lnpaymentdetails.amount.msatsInt < 0
                amount: lnpaymentdetails.fee
                timestamp: lnpaymentdetails.timestamp
            }

            Label {
                Layout.columnSpan: 2
                Layout.topMargin: constants.paddingSmall
                text: qsTr('Label')
                color: Material.accentColor
            }

            TextHighlightPane {
                id: labelContent

                property bool editmode: false

                Layout.columnSpan: 2
                Layout.fillWidth: true

                RowLayout {
                    width: parent.width
                    Label {
                        visible: !labelContent.editmode
                        text: lnpaymentdetails.label
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                        font.pixelSize: constants.fontSizeLarge
                    }
                    ToolButton {
                        visible: !labelContent.editmode
                        icon.source: '../../icons/pen.png'
                        icon.color: 'transparent'
                        onClicked: {
                            labelEdit.text = lnpaymentdetails.label
                            labelContent.editmode = true
                            labelEdit.focus = true
                        }
                    }
                    TextField {
                        id: labelEdit
                        visible: labelContent.editmode
                        text: lnpaymentdetails.label
                        font.pixelSize: constants.fontSizeLarge
                        Layout.fillWidth: true
                    }
                    ToolButton {
                        visible: labelContent.editmode
                        icon.source: '../../icons/confirmed.png'
                        icon.color: 'transparent'
                        onClicked: {
                            labelContent.editmode = false
                            lnpaymentdetails.setLabel(labelEdit.text)
                        }
                    }
                    ToolButton {
                        visible: labelContent.editmode
                        icon.source: '../../icons/closebutton.png'
                        icon.color: 'transparent'
                        onClicked: labelContent.editmode = false
                    }
                }
            }

            Heading {
                Layout.columnSpan: 2
                text: qsTr('Technical properties')
            }

            Label {
                Layout.columnSpan: 2
                Layout.topMargin: constants.paddingSmall
                text: qsTr('Payment hash')
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true

                RowLayout {
                    width: parent.width
                    Label {
                        text: lnpaymentdetails.paymentHash
                        font.pixelSize: constants.fontSizeLarge
                        font.family: FixedFont
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: 'transparent'
                        onClicked: {
                            var dialog = app.genericShareDialog.createObject(root,
                                { title: qsTr('Payment hash'), text: lnpaymentdetails.paymentHash }
                            )
                            dialog.open()
                        }
                    }
                }
            }

            Label {
                Layout.columnSpan: 2
                Layout.topMargin: constants.paddingSmall
                text: qsTr('Preimage')
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true

                RowLayout {
                    width: parent.width
                    Label {
                        text: lnpaymentdetails.preimage
                        font.pixelSize: constants.fontSizeLarge
                        font.family: FixedFont
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: 'transparent'
                        onClicked: {
                            var dialog = app.genericShareDialog.createObject(root,
                                { title: qsTr('Preimage'), text: lnpaymentdetails.preimage }
                            )
                            dialog.open()
                        }
                    }
                }
            }

        }
    }

    LnPaymentDetails {
        id: lnpaymentdetails
        wallet: Daemon.currentWallet
        key: root.key
        onLabelChanged: root.detailsChanged()
    }

}
