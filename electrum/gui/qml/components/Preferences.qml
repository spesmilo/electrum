import QtQuick 2.6
import QtQuick.Layouts 1.15
import QtQuick.Controls 2.3
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

Pane {
    id: preferences

    property string title: qsTr("Preferences")

    padding: 0

    property var _baseunits: ['BTC','mBTC','bits','sat']

    ColumnLayout {
        anchors.fill: parent

        Flickable {
            Layout.fillHeight: true
            Layout.fillWidth: true

            contentHeight: prefsPane.height
            interactive: height < contentHeight
            clip: true

            Pane {
                id: prefsPane
                GridLayout {
                    columns: 2
                    width: parent.width

                    Label {
                        text: qsTr('Language')
                    }

                    ElComboBox {
                        id: language
                        enabled: false
                    }

                    Label {
                        text: qsTr('Base unit')
                    }

                    ElComboBox {
                        id: baseUnit
                        model: _baseunits
                        onCurrentValueChanged: {
                            if (activeFocus)
                                Config.baseUnit = currentValue
                        }
                    }

                    Switch {
                        id: thousands
                        Layout.columnSpan: 2
                        text: qsTr('Add thousands separators to bitcoin amounts')
                        onCheckedChanged: {
                            if (activeFocus)
                                Config.thousandsSeparator = checked
                        }
                    }

                    Switch {
                        id: checkSoftware
                        Layout.columnSpan: 2
                        text: qsTr('Automatically check for software updates')
                        enabled: false
                    }

                    Switch {
                        id: fiatEnable
                        text: qsTr('Fiat Currency')
                        onCheckedChanged: {
                            if (activeFocus)
                                Daemon.fx.enabled = checked
                        }
                    }

                    ElComboBox {
                        id: currencies
                        model: Daemon.fx.currencies
                        enabled: Daemon.fx.enabled
                        onCurrentValueChanged: {
                            if (activeFocus)
                                Daemon.fx.fiatCurrency = currentValue
                        }
                    }

                    Switch {
                        id: historicRates
                        text: qsTr('Historic rates')
                        enabled: Daemon.fx.enabled
                        Layout.columnSpan: 2
                        onCheckedChanged: {
                            if (activeFocus)
                                Daemon.fx.historicRates = checked
                        }
                    }

                    Label {
                        text: qsTr('Source')
                        enabled: Daemon.fx.enabled
                    }

                    ElComboBox {
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

                    Switch {
                        id: spendUnconfirmed
                        text: qsTr('Spend unconfirmed')
                        Layout.columnSpan: 2
                        onCheckedChanged: {
                            if (activeFocus)
                                Config.spendUnconfirmed = checked
                        }
                    }

                    Switch {
                        id: useRbf
                        text: qsTr('Use Replace-By-Fee')
                        Layout.columnSpan: 2
                        onCheckedChanged: {
                            if (activeFocus)
                                Config.useRbf = checked
                        }
                    }

                    Label {
                        text: qsTr('Default request expiry')
                        Layout.fillWidth: false
                    }

                    RequestExpiryComboBox {
                        onCurrentValueChanged: {
                            if (activeFocus)
                                Config.requestExpiry = currentValue
                        }
                    }

                    Label {
                        text: qsTr('PIN')
                    }

                    RowLayout {
                        Label {
                            text: Config.pinCode == '' ? qsTr('Off'): qsTr('On')
                            color: Material.accentColor
                            Layout.rightMargin: constants.paddingMedium
                        }
                        Button {
                            text: qsTr('Enable')
                            visible: Config.pinCode == ''
                            onClicked: {
                                var dialog = pinSetup.createObject(preferences, {mode: 'enter'})
                                dialog.accepted.connect(function() {
                                    Config.pinCode = dialog.pincode
                                    dialog.close()
                                })
                                dialog.open()
                            }
                        }
                        Button {
                            text: qsTr('Change')
                            visible: Config.pinCode != ''
                            onClicked: {
                                var dialog = pinSetup.createObject(preferences, {mode: 'change', pincode: Config.pinCode})
                                dialog.accepted.connect(function() {
                                    Config.pinCode = dialog.pincode
                                    dialog.close()
                                })
                                dialog.open()
                            }
                        }
                        Button {
                            text: qsTr('Remove')
                            visible: Config.pinCode != ''
                            onClicked: {
                                Config.pinCode = ''
                            }
                        }
                    }

                    Label {
                        text: qsTr('Lightning Routing')
                    }

                    ElComboBox {
                        id: lnRoutingType
                        enabled: Daemon.currentWallet && Daemon.currentWallet.isLightning

                        valueRole: 'key'
                        textRole: 'label'
                        model: ListModel {
                            ListElement { key: 'gossip'; label: qsTr('Gossip') }
                            ListElement { key: 'trampoline'; label: qsTr('Trampoline') }
                        }
                        onCurrentValueChanged: {
                            if (activeFocus)
                                Config.useGossip = currentValue == 'gossip'
                        }
                    }

                    Switch {
                        id: useRecoverableChannels
                        text: qsTr('Create recoverable channels')
                        Layout.columnSpan: 2
                        onCheckedChanged: {
                            if (activeFocus)
                                Config.useRecoverableChannels = checked
                        }
                    }

                    Switch {
                        id: useFallbackAddress
                        text: qsTr('Use onchain fallback address for Lightning invoices')
                        Layout.columnSpan: 2
                        onCheckedChanged: {
                            if (activeFocus)
                                Config.useFallbackAddress = checked
                        }
                    }

                    Switch {
                        id: enableDebugLogs
                        text: qsTr('Enable debug logs (for developers)')
                        Layout.columnSpan: 2
                        onCheckedChanged: {
                            if (activeFocus)
                                Config.enableDebugLogs = checked
                        }
                        enabled: Config.canToggleDebugLogs
                    }

                }

            }
        }

    }

    Component {
        id: pinSetup
        Pin {}
    }

    Component.onCompleted: {
        baseUnit.currentIndex = _baseunits.indexOf(Config.baseUnit)
        thousands.checked = Config.thousandsSeparator
        currencies.currentIndex = currencies.indexOfValue(Daemon.fx.fiatCurrency)
        historicRates.checked = Daemon.fx.historicRates
        rateSources.currentIndex = rateSources.indexOfValue(Daemon.fx.rateSource)
        fiatEnable.checked = Daemon.fx.enabled
        spendUnconfirmed.checked = Config.spendUnconfirmed
        lnRoutingType.currentIndex = Config.useGossip ? 0 : 1
        useFallbackAddress.checked = Config.useFallbackAddress
        enableDebugLogs.checked = Config.enableDebugLogs
        useRbf.checked = Config.useRbf
        useRecoverableChannels.checked = Config.useRecoverableChannels
    }
}
