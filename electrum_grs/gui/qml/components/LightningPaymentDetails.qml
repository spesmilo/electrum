import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: root
    width: parent.width
    height: parent.height

    // property string title: qsTr("Lightning payment details")

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

            Label {
                Layout.columnSpan: 2
                text: qsTr('Lightning payment details')
                font.pixelSize: constants.fontSizeLarge
                color: Material.accentColor
            }

            Rectangle {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                height: 1
                color: Material.accentColor
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

            RowLayout {
                Label {
                    text: Config.formatMilliSats(lnpaymentdetails.amount)
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Label {
                visible: lnpaymentdetails.amount.msatsInt < 0
                text: qsTr('Transaction fee')
                color: Material.accentColor
            }

            RowLayout {
                visible: lnpaymentdetails.amount.msatsInt < 0
                Label {
                    text: Config.formatMilliSats(lnpaymentdetails.fee)
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Label {
                text: qsTr('Label')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            TextHighlightPane {
                id: labelContent

                property bool editmode: false

                Layout.columnSpan: 2
                Layout.fillWidth: true
                padding: 0
                leftPadding: constants.paddingSmall

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
                            lnpaymentdetails.set_label(labelEdit.text)
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

            Label {
                text: qsTr('Payment hash')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                padding: 0
                leftPadding: constants.paddingSmall

                RowLayout {
                    width: parent.width
                    Label {
                        text: lnpaymentdetails.payment_hash
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
                                { title: qsTr('Payment hash'), text: lnpaymentdetails.payment_hash }
                            )
                            dialog.open()
                        }
                    }
                }
            }

            Label {
                text: qsTr('Preimage')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                padding: 0
                leftPadding: constants.paddingSmall

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

            Label {
                text: qsTr('Lightning invoice')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            TextHighlightPane {
                Layout.columnSpan: 2
                Layout.fillWidth: true
                padding: 0
                leftPadding: constants.paddingSmall

                RowLayout {
                    width: parent.width
                    Label {
                        Layout.fillWidth: true
                        text: lnpaymentdetails.invoice
                        font.pixelSize: constants.fontSizeLarge
                        font.family: FixedFont
                        wrapMode: Text.Wrap
                        maximumLineCount: 3
                        elide: Text.ElideRight
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: enabled ? 'transparent' : constants.mutedForeground
                        enabled: lnpaymentdetails.invoice != ''
                        onClicked: {
                            var dialog = app.genericShareDialog.createObject(root,
                                { title: qsTr('Lightning Invoice'), text: lnpaymentdetails.invoice }
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
