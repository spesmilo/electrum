import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    id: rootItem
    visible: Daemon.currentWallet !== undefined
    clip: true

    ListView {
        id: listview
        width: parent.width
        height: parent.height

        model: Daemon.currentWallet.historyModel

        delegate: Item {
            id: delegate
            width: ListView.view.width
            height: delegateLayout.height

            ColumnLayout {
                id: delegateLayout
                width: parent.width
                spacing: 0

                Rectangle {
                    visible: index > 0
                    Layout.fillWidth: true
                    Layout.preferredHeight: constants.paddingSmall
                    color: Qt.rgba(0,0,0,0.10)
                }


                ItemDelegate {
                    Layout.fillWidth: true
                    Layout.preferredHeight: txinfo.height

                    GridLayout {
                        id: txinfo
                        columns: 3

                        x: constants.paddingSmall
                        width: delegate.width - 2*constants.paddingSmall

                        Item { Layout.columnSpan: 3; Layout.preferredWidth: 1; Layout.preferredHeight: 1}
                        Image {
                            readonly property variant tx_icons : [
                                "../../../gui/icons/unconfirmed.png",
                                "../../../gui/icons/clock1.png",
                                "../../../gui/icons/clock2.png",
                                "../../../gui/icons/clock3.png",
                                "../../../gui/icons/clock4.png",
                                "../../../gui/icons/clock5.png",
                                "../../../gui/icons/confirmed.png"
                            ]

                            Layout.preferredWidth: constants.iconSizeLarge
                            Layout.preferredHeight: constants.iconSizeLarge
                            Layout.alignment: Qt.AlignVCenter
                            Layout.rowSpan: 2
                            source: tx_icons[Math.min(6,model.confirmations)]
                        }

                        Label {
                            font.pixelSize: constants.fontSizeLarge
                            Layout.fillWidth: true
                            text: model.label !== '' ? model.label : '<no label>'
                            color: model.label !== '' ? Material.accentColor : 'gray'
                            wrapMode: Text.Wrap
                            maximumLineCount: 2
                            elide: Text.ElideRight
                        }
                        Label {
                            id: valueLabel
                            font.family: FixedFont
                            font.pixelSize: constants.fontSizeMedium
                            text: Config.formatSats(model.bc_value)
                            font.bold: true
                            color: model.incoming ? constants.colorCredit : constants.colorDebit
                        }
                        Label {
                            font.pixelSize: constants.fontSizeSmall
                            text: model.date
                        }
                        Label {
                            font.pixelSize: constants.fontSizeXSmall
                            Layout.alignment: Qt.AlignRight
                            text: model.fee !== undefined ? 'fee: ' + model.fee : ''
                        }
                        Item { Layout.columnSpan: 3; Layout.preferredWidth: 1; Layout.preferredHeight: 1 }
                    }
                }
            }
            // as the items in the model are not bindings to QObjects,
            // hook up events that might change the appearance
            Connections {
                target: Config
                function onBaseUnitChanged() {
                    valueLabel.text = Config.formatSats(model.bc_value)
                }
                function onThousandsSeparatorChanged() {
                    valueLabel.text = Config.formatSats(model.bc_value)
                }
            }

        } // delegate

        ScrollIndicator.vertical: ScrollIndicator { }

    }

    Connections {
        target: Network
        function onHeightChanged(height) {
            Daemon.currentWallet.historyModel.updateBlockchainHeight(height)
        }
    }
}
