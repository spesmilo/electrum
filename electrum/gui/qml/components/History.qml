import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0
import QtQml.Models 2.2

import org.electrum 1.0

Pane {
    id: rootItem
    visible: Daemon.currentWallet !== undefined
    clip: true

    ListView {
        id: listview
        width: parent.width
        height: parent.height

        model: visualModel

        section.property: 'section'
        section.criteria: ViewSection.FullString
        section.delegate: RowLayout {
            width: ListView.view.width
            required property string section
            Label {
                text: section == 'today'
                        ? qsTr('Today')
                        : section == 'yesterday'
                            ? qsTr('Yesterday')
                            : section == 'lastweek'
                                ? qsTr('Last week')
                                : section == 'lastmonth'
                                    ? qsTr('Last month')
                                    : qsTr('Older')
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: constants.paddingLarge
                font.pixelSize: constants.fontSizeLarge
                color: Material.accentColor
            }
        }

        DelegateModel {
            id: visualModel
            model: Daemon.currentWallet.historyModel

            groups: [
                DelegateModelGroup { name: 'today'; includeByDefault: false },
                DelegateModelGroup { name: 'yesterday'; includeByDefault: false },
                DelegateModelGroup { name: 'lastweek'; includeByDefault: false },
                DelegateModelGroup { name: 'lastmonth'; includeByDefault: false },
                DelegateModelGroup { name: 'older'; includeByDefault: false }
            ]

            delegate: Item {
                id: delegate
                width: ListView.view.width
                height: delegateLayout.height

                ColumnLayout {
                    id: delegateLayout
                    width: parent.width
                    spacing: 0

                    ItemDelegate {
                        Layout.fillWidth: true
                        Layout.preferredHeight: txinfo.height

                        onClicked: {
                            if (model.lightning) {
                                var page = app.stack.push(Qt.resolvedUrl('LightningPaymentDetails.qml'), {'key': model.key})
                                page.detailsChanged.connect(function() {
                                    // update listmodel when details change
                                    visualModel.model.update_tx_label(model.key, page.label)
                                })
                            } else {
                                var page = app.stack.push(Qt.resolvedUrl('TxDetails.qml'), {'txid': model.key})
                                page.detailsChanged.connect(function() {
                                    // update listmodel when details change
                                    visualModel.model.update_tx_label(model.key, page.label)
                                })
                            }
                        }

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
                                    "../../../gui/icons/confirmed_bw.png"
                                ]

                                Layout.preferredWidth: constants.iconSizeLarge
                                Layout.preferredHeight: constants.iconSizeLarge
                                Layout.alignment: Qt.AlignVCenter
                                Layout.rowSpan: 2
                                source: model.lightning ? "../../../gui/icons/lightning.png" : tx_icons[Math.min(6,model.confirmations)]
                            }

                            Label {
                                Layout.fillWidth: true
                                font.pixelSize: model.label !== '' ? constants.fontSizeLarge : constants.fontSizeMedium
                                text: model.label !== '' ? model.label : '<no label>'
                                color: model.label !== '' ? Material.foreground : constants.mutedForeground
                                wrapMode: Text.Wrap
                                maximumLineCount: 2
                                elide: Text.ElideRight
                            }
                            Label {
                                id: valueLabel
                                font.family: FixedFont
                                font.pixelSize: constants.fontSizeMedium
                                Layout.alignment: Qt.AlignRight
                                font.bold: true
                                color: model.incoming ? constants.colorCredit : constants.colorDebit

                                function updateText() {
                                    text = Config.formatSats(model.value)
                                }
                                Component.onCompleted: updateText()
                            }
                            Label {
                                font.pixelSize: constants.fontSizeSmall
                                text: model.date
                                color: constants.mutedForeground
                            }
                            Label {
                                id: fiatLabel
                                font.pixelSize: constants.fontSizeSmall
                                Layout.alignment: Qt.AlignRight
                                color: constants.mutedForeground

                                function updateText() {
                                    if (!Daemon.fx.enabled) {
                                        text = ''
                                    } else if (Daemon.fx.historicRates) {
                                        text = Daemon.fx.fiatValueHistoric(model.value, model.timestamp) + ' ' + Daemon.fx.fiatCurrency
                                    } else {
                                        text = Daemon.fx.fiatValue(model.value, false) + ' ' + Daemon.fx.fiatCurrency
                                    }
                                }
                                Component.onCompleted: updateText()
                            }
                            Item { Layout.columnSpan: 3; Layout.preferredWidth: 1; Layout.preferredHeight: 1 }
                        }
                    }

                    Rectangle {
                        visible: delegate.ListView.section == delegate.ListView.nextSection
                        Layout.fillWidth: true
                        Layout.preferredHeight: constants.paddingTiny
                        color: Qt.rgba(0,0,0,0.10)
                    }

                }
                // as the items in the model are not bindings to QObjects,
                // hook up events that might change the appearance
                Connections {
                    target: Config
                    function onBaseUnitChanged() { valueLabel.updateText() }
                    function onThousandsSeparatorChanged() { valueLabel.updateText() }
                }

                Connections {
                    target: Daemon.fx
                    function onHistoricRatesChanged() { fiatLabel.updateText() }
                    function onQuotesUpdated() { fiatLabel.updateText() }
                    function onHistoryUpdated() { fiatLabel.updateText() }
                    function onEnabledUpdated() { fiatLabel.updateText() }
                }

                Component.onCompleted: {
                    if (model.section == 'today') {
                        delegate.DelegateModel.inToday = true
                    } else if (model.section == 'yesterday') {
                        delegate.DelegateModel.inYesterday = true
                    } else if (model.section == 'lastweek') {
                        delegate.DelegateModel.inLastweek = true
                    } else if (model.section == 'lastmonth') {
                        delegate.DelegateModel.inLastmonth = true
                    } else if (model.section == 'older') {
                        delegate.DelegateModel.inOlder = true
                    }
                }

            } // delegate
        }

        ScrollIndicator.vertical: ScrollIndicator { }

    }

    Connections {
        target: Network
        function onHeightChanged(height) {
            Daemon.currentWallet.historyModel.updateBlockchainHeight(height)
        }
    }
}
