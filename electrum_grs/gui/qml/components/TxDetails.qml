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

            Label {
                text: qsTr('Status')
                color: Material.accentColor
            }

            Label {
                text: txdetails.status
            }

            Label {
                text: qsTr('Mempool depth')
                color: Material.accentColor
                visible: !txdetails.isMined
            }

            Label {
                text: txdetails.mempoolDepth
                visible: !txdetails.isMined
            }

            Label {
                text: qsTr('Date')
                color: Material.accentColor
            }

            Label {
                text: txdetails.date
            }

            Label {
                text: txdetails.amount.satsInt > 0
                        ? qsTr('Amount received')
                        : qsTr('Amount sent')
                color: Material.accentColor
            }

            RowLayout {
                Label {
                    text: Config.formatSats(txdetails.amount)
                    font.family: FixedFont
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }

            Label {
                visible: txdetails.amount.satsInt < 0
                text: qsTr('Transaction fee')
                color: Material.accentColor
            }

            RowLayout {
                visible: txdetails.amount.satsInt < 0
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
                        onClicked: {
                            var dialog = share.createObject(root, { 'title': qsTr('Transaction ID'), 'text': root.txid })
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

        }
    }

    TxDetails {
        id: txdetails
        wallet: Daemon.currentWallet
        txid: root.txid
        onLabelChanged: root.detailsChanged()
    }

    Component {
        id: share
        GenericShareDialog {}
    }

}
