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

                CheckBox {
                    id: fiatEnable
                    text: qsTr('Fiat Currency')
                    onCheckedChanged: {
                        if (activeFocus)
                            Daemon.fx.enabled = checked
                    }
                }

                ComboBox {
                    id: currencies
                    model: Daemon.fx.currencies
                    enabled: Daemon.fx.enabled
                    onCurrentValueChanged: {
                        if (activeFocus)
                            Daemon.fx.fiatCurrency = currentValue
                    }
                }

                CheckBox {
                    id: historicRates
                    text: qsTr('Historic rates')
                    enabled: Daemon.fx.enabled
                    Layout.columnSpan: 2
                    onCheckStateChanged: {
                        if (activeFocus)
                            Daemon.fx.historicRates = checked
                    }
                }

                Label {
                    text: qsTr('Source')
                    enabled: Daemon.fx.enabled
                }

                ComboBox {
                    id: rateSources
                    enabled: Daemon.fx.enabled
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
        historicRates.checked = Daemon.fx.historicRates
        rateSources.currentIndex = rateSources.indexOfValue(Daemon.fx.rateSource)
        fiatEnable.checked = Daemon.fx.enabled
    }
}
