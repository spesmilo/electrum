import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

Pane {
    property string title: qsTr("Preferences")

    ColumnLayout {
        anchors.fill: parent

        Flickable {
            Layout.fillHeight: true
            Layout.fillWidth: true

            GridLayout {
                id: rootLayout
                columns: 2

                Label {
                    text: qsTr('Language')
                }

                ComboBox {
                    id: language
                    enabled: false
                }

                Label {
                    text: qsTr('Base unit')
                }

                ComboBox {
                    id: baseUnit
                    model: ['BTC','mBTC','bits','sat']
                    onCurrentValueChanged: {
                        if (activeFocus)
                            Config.baseUnit = currentValue
                    }
                }

                CheckBox {
                    id: thousands
                    Layout.columnSpan: 2
                    text: qsTr('Add thousands separators to bitcoin amounts')
                    onCheckedChanged: {
                        if (activeFocus)
                            Config.thousandsSeparator = checked
                    }
                }

                CheckBox {
                    id: checkSoftware
                    Layout.columnSpan: 2
                    text: qsTr('Automatically check for software updates')
                    enabled: false
                }

                Label {
                    text: qsTr('Fiat Currency')
                }

                ComboBox {
                    id: currencies
                    model: Daemon.fx.currencies
                    onCurrentValueChanged: {
                        if (activeFocus)
                            Daemon.fx.fiatCurrency = currentValue
                    }
                }

                CheckBox {
                    id: historyRates
                    text: qsTr('History rates')
                    enabled: currencies.currentValue != ''
                    Layout.columnSpan: 2
                    onCheckStateChanged: {
                        if (activeFocus)
                            Daemon.fx.historyRates = checked
                    }
                }

                Label {
                    text: qsTr('Source')
                    enabled: currencies.currentValue != ''
                }

                ComboBox {
                    id: rateSources
                    enabled: currencies.currentValue != ''
                    model: Daemon.fx.rateSources
                    onModelChanged: {
                        currentIndex = rateSources.indexOfValue(Daemon.fx.rateSource)
                    }
                    onCurrentValueChanged: {
                        if (activeFocus)
                            Daemon.fx.rateSource = currentValue
                    }
                }
            }

        }

    }

    Component.onCompleted: {
        baseUnit.currentIndex = ['BTC','mBTC','bits','sat'].indexOf(Config.baseUnit)
        thousands.checked = Config.thousandsSeparator
        currencies.currentIndex = currencies.indexOfValue(Daemon.fx.fiatCurrency)
        historyRates.checked = Daemon.fx.historyRates
        rateSources.currentIndex = rateSources.indexOfValue(Daemon.fx.rateSource)
    }
}
