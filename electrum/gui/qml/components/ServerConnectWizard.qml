import QtQuick 2.6
import QtQuick.Layouts 1.0
import QtQuick.Controls 2.15
import QtQuick.Controls.Material 2.15

Wizard {
    id: serverconnectwizard

    title: qsTr('How do you want to connect to a server?')

    enter: null // disable transition

    onAccepted: {
        var proxy = wizard_data['proxy']
        if (proxy && proxy['enabled'] == true) {
            Network.proxy = proxy
        } else {
            Network.proxy = {'enabled': false}
        }
        Config.autoConnect = wizard_data['autoconnect']
        if (!wizard_data['autoconnect']) {
            Network.server = wizard_data['server']
        }
    }

    Component.onCompleted: {
        var start = _loadNextComponent(autoconnect)
        start.next.connect(function() {autoconnectDone()})
    }

    function autoconnectDone() {
        var page = _loadNextComponent(proxyconfig, wizard_data)
        page.next.connect(function() {proxyconfigDone()})
    }

    function proxyconfigDone() {
        var page = _loadNextComponent(serverconfig, wizard_data)
    }

    property Component autoconnect: Component {
        WizardComponent {
            valid: true
            last: serverconnectgroup.checkedButton.connecttype === 'auto'

            onAccept: {
                wizard_data['autoconnect'] = serverconnectgroup.checkedButton.connecttype === 'auto'
            }

            ColumnLayout {
                anchors.fill: parent

                Text {
                    text: qsTr('Electrum communicates with remote servers to get information about your transactions and addresses. The servers all fulfill the same purpose only differing in hardware. In most cases you simply want to let Electrum pick one at random.  However if you prefer feel free to select a server manually.')
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    color: Material.primaryTextColor
                }

                ButtonGroup {
                    id: serverconnectgroup
                }

                RadioButton {
                    ButtonGroup.group: serverconnectgroup
                    property string connecttype: 'auto'
                    text: qsTr('Auto connect')
                }
                RadioButton {
                    ButtonGroup.group: serverconnectgroup
                    property string connecttype: 'manual'
                    checked: true
                    text: qsTr('Select servers manually')
                }

            }

        }
    }

    property Component proxyconfig: Component {
        WizardComponent {
            valid: true
            last: false

            onAccept: {
                var p = {}
                p['enabled'] = proxy_enabled.checked
                if (proxy_enabled.checked) {
                    var type = proxytype.currentValue.toLowerCase()
                    if (type == 'tor')
                        type = 'socks5'
                    p['mode'] = type
                    p['host'] = address.text
                    p['port'] = port.text
                    p['user'] = username.text
                    p['password'] = password.text
                }
                wizard_data['proxy'] = p
            }

            ColumnLayout {
                anchors.fill: parent

                Text {
                    text: qsTr('Proxy settings')
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    color: Material.primaryTextColor
                }

                CheckBox {
                    id: proxy_enabled
                    text: qsTr('Enable Proxy')
                }

                ComboBox {
                    id: proxytype
                    enabled: proxy_enabled.checked
                    model: ['TOR', 'SOCKS5', 'SOCKS4']
                    onCurrentIndexChanged: {
                        if (currentIndex == 0) {
                            address.text = "127.0.0.1"
                            port.text = "9050"
                        }
                    }
                }

                GridLayout {
                    columns: 4
                    Layout.fillWidth: true

                    Label {
                        text: qsTr("Address")
                        enabled: address.enabled
                    }

                    TextField {
                        id: address
                        enabled: proxytype.enabled && proxytype.currentIndex > 0
                    }

                    Label {
                        text: qsTr("Port")
                        enabled: port.enabled
                    }

                    TextField {
                        id: port
                        enabled: proxytype.enabled && proxytype.currentIndex > 0
                    }

                    Label {
                        text: qsTr("Username")
                        enabled: username.enabled
                    }

                    TextField {
                        id: username
                        enabled: proxytype.enabled && proxytype.currentIndex > 0
                    }

                    Label {
                        text: qsTr("Password")
                        enabled: password.enabled
                    }

                    TextField {
                        id: password
                        enabled: proxytype.enabled && proxytype.currentIndex > 0
                        echoMode: TextInput.Password
                    }
                }
            }

        }
    }

    property Component serverconfig: Component {
        WizardComponent {
            valid: true
            last: true

            onAccept: {
                wizard_data['oneserver'] = !auto_server.checked
                wizard_data['server'] = address.text
            }

            ColumnLayout {
                anchors.fill: parent

                Text {
                    text: qsTr('Server settings')
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                    color: Material.primaryTextColor
                }

                CheckBox {
                    id: auto_server
                    text: qsTr('Select server automatically')
                    checked: true
                }

                GridLayout {
                    columns: 2
                    Layout.fillWidth: true

                    Label {
                        text: qsTr("Server")
                        enabled: address.enabled
                    }

                    TextField {
                        id: address
                        enabled: !auto_server.checked
                    }
                }
            }

        }
    }

}
