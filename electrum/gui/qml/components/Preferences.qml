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

        TabBar {
            id: tabbar
            Layout.fillWidth: true
            currentIndex: swipeview.currentIndex
            TabButton {
                text: qsTr('Preferences')
                font.pixelSize: constants.fontSizeLarge
            }
            TabButton {
                text: qsTr('Plugins')
                font.pixelSize: constants.fontSizeLarge
            }
        }

        SwipeView {
            id: swipeview

            Layout.fillHeight: true
            Layout.fillWidth: true
            currentIndex: tabbar.currentIndex

            Flickable {
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
                    }

                }
            }

            Pane {
                ColumnLayout {
                    x: constants.paddingXXLarge
                    id: pluginsRootLayout
                }
            }
        }

    }

    Component {
        id: pinSetup
        Pin {}
    }

    Component {
        id: pluginHeader
        RowLayout {
            Layout.leftMargin: -constants.paddingXXLarge
            property string name
            property string fullname
            property bool pluginEnabled
            Switch {
                checked: pluginEnabled
                onCheckedChanged: {
                    if (activeFocus)
                        pluginEnabled = checked
                }
            }
            Label {
                text: fullname
            }
            onPluginEnabledChanged: {
                console.log('!')
                AppController.setPluginEnabled(name, pluginEnabled)
            }
        }
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

        var plugins = AppController.plugins
        for (var i=0; i<plugins.length; i++) {
            var p = plugins[i]
            pluginHeader.createObject(pluginsRootLayout, { name: p['name'], fullname: p['fullname'], pluginEnabled: p['enabled'] })
            var labelsPlugin = AppController.plugin(p['name'])
            if (labelsPlugin) {
                if (labelsPlugin.settingsComponent()) {
                    var component = Qt.createComponent(Qt.resolvedUrl(labelsPlugin.settingsComponent()))
                    component.createObject(pluginsRootLayout, { plugin: labelsPlugin })
                }
            }
        }
    }
}
