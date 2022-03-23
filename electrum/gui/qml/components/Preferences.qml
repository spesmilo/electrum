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
                }

                CheckBox {
                    id: thousands
                    Layout.columnSpan: 2
                    text: qsTr('Add thousands separators to bitcoin amounts')
                }

                CheckBox {
                    id: checkSoftware
                    Layout.columnSpan: 2
                    text: qsTr('Automatically check for software updates')
                    enabled: false
                }

                CheckBox {
                    id: writeLogs
                    Layout.columnSpan: 2
                    text: qsTr('Write logs to file')
                    enabled: false
                }
            }

        }

        RowLayout {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignHCenter
            Button {
                text: qsTr('Save')
                onClicked: save()
            }
        }
    }

    function save() {
        Config.baseUnit = baseUnit.currentValue
        Config.thousandsSeparator = thousands.checked
        app.stack.pop()
    }

    Component.onCompleted: {
        baseUnit.currentIndex = ['BTC','mBTC','bits','sat'].indexOf(Config.baseUnit)
        thousands.checked = Config.thousandsSeparator
    }
}
