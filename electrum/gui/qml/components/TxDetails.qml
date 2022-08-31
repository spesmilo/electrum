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

    property string title: qsTr("Transaction details")

    property string txid
    property string rawtx

    property alias label: txdetails.label

    signal detailsChanged

    property QtObject menu: Menu {
        id: menu
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Bump fee')
                enabled: txdetails.canBump
                //onTriggered:
            }
        }
        MenuItem {
            icon.color: 'transparent'
            action: Action {
                text: qsTr('Cancel double-spend')
                enabled: txdetails.canCancel
            }
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: rootLayout.height
        clip: true
        interactive: height < contentHeight

        GridLayout {
            id: rootLayout
            width: parent.width
            columns: 2

            RowLayout {
                Layout.fillWidth: true
                Layout.columnSpan: 2
                visible: txdetails.isUnrelated
                Image {
                    source: '../../icons/warning.png'
                    Layout.preferredWidth: constants.iconSizeSmall
                    Layout.preferredHeight: constants.iconSizeSmall
                }
                Label {
                    text: qsTr('Transaction is unrelated to this wallet')
                    color: Material.accentColor
                }
            }

            Label {
                Layout.fillWidth: true
                visible: !txdetails.isUnrelated && txdetails.lnAmount.satsInt == 0
                text: txdetails.amount.satsInt > 0
                        ? qsTr('Amount received')
                        : qsTr('Amount sent')
                color: Material.accentColor
            }

            Label {
                Layout.fillWidth: true
                visible: !txdetails.isUnrelated && txdetails.lnAmount.satsInt != 0
                text: txdetails.lnAmount.satsInt > 0
                        ? qsTr('Amount received in channels')
                        : qsTr('Amount withdrawn from channels')
                color: Material.accentColor
                wrapMode: Text.Wrap
            }

            RowLayout {
                visible: !txdetails.isUnrelated
                Layout.fillWidth: true
                Label {
                    visible: txdetails.lnAmount.satsInt == 0
                    text: Config.formatSats(txdetails.amount)
                    font.family: FixedFont
                }
                Label {
                    visible: txdetails.lnAmount.satsInt != 0
                    text: Config.formatSats(txdetails.lnAmount)
                    font.family: FixedFont
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Item {
                visible: !txdetails.isUnrelated && Daemon.fx.enabled; Layout.preferredWidth: 1; Layout.preferredHeight: 1
            }

            Label {
                visible: !txdetails.isUnrelated && Daemon.fx.enabled && txdetails.lnAmount.satsInt == 0
                text: Daemon.fx.fiatValue(txdetails.amount, false) + ' ' + Daemon.fx.fiatCurrency
            }

            Label {
                visible: !txdetails.isUnrelated && Daemon.fx.enabled && txdetails.lnAmount.satsInt != 0
                text: Daemon.fx.fiatValue(txdetails.lnAmount, false) + ' ' + Daemon.fx.fiatCurrency
            }


            Label {
                Layout.fillWidth: true
                visible: txdetails.fee.satsInt != 0
                text: qsTr('Transaction fee')
                color: Material.accentColor
            }

            RowLayout {
                Layout.fillWidth: true
                visible: txdetails.fee.satsInt != 0
                Label {
                    text: Config.formatSats(txdetails.fee)
                    font.family: FixedFont
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Label {
                text: qsTr('Status')
                color: Material.accentColor
            }

            Label {
                Layout.fillWidth: true
                text: txdetails.status
            }

            Label {
                text: qsTr('Mempool depth')
                color: Material.accentColor
                visible: !txdetails.isMined && txdetails.canBroadcast
            }

            Label {
                text: txdetails.mempoolDepth
                visible: !txdetails.isMined && txdetails.canBroadcast
            }

            Label {
                visible: txdetails.isMined
                text: qsTr('Date')
                color: Material.accentColor
            }

            Label {
                visible: txdetails.isMined
                text: txdetails.date
            }

            Label {
                visible: txdetails.isMined
                text: qsTr('Height')
                color: Material.accentColor
            }

            Label {
                visible: txdetails.isMined
                text: txdetails.height
            }

            Label {
                visible: txdetails.isMined
                text: qsTr('TX index')
                color: Material.accentColor
            }

            Label {
                visible: txdetails.isMined
                text: txdetails.txpos
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
                        text: txdetails.label
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                        font.pixelSize: constants.fontSizeLarge
                    }
                    ToolButton {
                        visible: !labelContent.editmode
                        icon.source: '../../icons/pen.png'
                        icon.color: 'transparent'
                        onClicked: {
                            labelEdit.text = txdetails.label
                            labelContent.editmode = true
                            labelEdit.focus = true
                        }
                    }
                    TextField {
                        id: labelEdit
                        visible: labelContent.editmode
                        text: txdetails.label
                        font.pixelSize: constants.fontSizeLarge
                        Layout.fillWidth: true
                    }
                    ToolButton {
                        visible: labelContent.editmode
                        icon.source: '../../icons/confirmed.png'
                        icon.color: 'transparent'
                        onClicked: {
                            labelContent.editmode = false
                            txdetails.set_label(labelEdit.text)
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
                text: qsTr('Transaction ID')
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
                        text: root.txid
                        font.pixelSize: constants.fontSizeLarge
                        font.family: FixedFont
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                    }
                    ToolButton {
                        icon.source: '../../icons/share.png'
                        icon.color: 'transparent'
                        enabled: root.txid
                        onClicked: {
                            var dialog = app.genericShareDialog.createObject(root,
                                { title: qsTr('Transaction ID'), text: root.txid }
                            )
                            dialog.open()
                        }
                    }
                }
            }

            Label {
                text: qsTr('Outputs')
                Layout.columnSpan: 2
                color: Material.accentColor
            }

            Repeater {
                model: txdetails.outputs
                delegate: TextHighlightPane {
                    Layout.columnSpan: 2
                    Layout.fillWidth: true
                    padding: 0
                    leftPadding: constants.paddingSmall
                    RowLayout {
                        width: parent.width
                        Label {
                            text: modelData.address
                            Layout.fillWidth: true
                            wrapMode: Text.Wrap
                            font.pixelSize: constants.fontSizeLarge
                            font.family: FixedFont
                            color: modelData.is_mine ? constants.colorMine : Material.foreground
                        }
                        Label {
                            text: Config.formatSats(modelData.value)
                            font.pixelSize: constants.fontSizeMedium
                            font.family: FixedFont
                        }
                        Label {
                            text: Config.baseUnit
                            font.pixelSize: constants.fontSizeMedium
                            color: Material.accentColor
                        }
                    }
                }
            }

            RowLayout {
                visible: !txdetails.isMined && !txdetails.isUnrelated
                Layout.columnSpan: 2
                Button {
                    text: qsTr('Sign')
                    enabled: !txdetails.isComplete
                    onClicked: txdetails.sign()
                }
                Button {
                    text: qsTr('Broadcast')
                    enabled: txdetails.canBroadcast
                    onClicked: txdetails.broadcast()
                }
            }
        }
    }

    TxDetails {
        id: txdetails
        wallet: Daemon.currentWallet
        txid: root.txid
        rawtx: root.rawtx
        onLabelChanged: root.detailsChanged()
    }
}
