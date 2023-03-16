import QtQuick 2.6
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.0
import QtQuick.Controls.Material 2.0

import org.electrum 1.0

import "controls"

ElDialog {
    id: root

    required property QtObject swaphelper

    width: parent.width
    height: parent.height

    title: qsTr('Lightning Swap')
    iconSource: Qt.resolvedUrl('../../icons/update.png')

    modal: true
    parent: Overlay.overlay
    Overlay.modal: Rectangle {
        color: "#aa000000"
    }

    padding: 0

    ColumnLayout {
        width: parent.width
        height: parent.height
        spacing: 0

        GridLayout {
            id: layout
            columns: 2
            Layout.preferredWidth: parent.width
            Layout.leftMargin: constants.paddingLarge
            Layout.rightMargin: constants.paddingLarge

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    Layout.preferredWidth: 1
                    Layout.fillWidth: true
                    text: qsTr('You send')
                    color: Material.accentColor
                }
                Image {
                    Layout.preferredWidth: constants.iconSizeSmall
                    Layout.preferredHeight: constants.iconSizeSmall
                    source: swaphelper.isReverse
                        ? '../../icons/lightning.png'
                        : '../../icons/bitcoin.png'
                    visible: swaphelper.valid
                }
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    id: tosend
                    text: Config.formatSats(swaphelper.tosend)
                    font.family: FixedFont
                    visible: swaphelper.valid
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                    visible: swaphelper.valid
                }
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    Layout.preferredWidth: 1
                    Layout.fillWidth: true
                    text: qsTr('You receive')
                    color: Material.accentColor
                }
                Image {
                    Layout.preferredWidth: constants.iconSizeSmall
                    Layout.preferredHeight: constants.iconSizeSmall
                    source: swaphelper.isReverse
                        ? '../../icons/bitcoin.png'
                        : '../../icons/lightning.png'
                    visible: swaphelper.valid
                }
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    id: toreceive
                    text: Config.formatSats(swaphelper.toreceive)
                    font.family: FixedFont
                    visible: swaphelper.valid
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                    visible: swaphelper.valid
                }
            }

            Label {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                text: qsTr('Server fee')
                color: Material.accentColor
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    text: Config.formatSats(swaphelper.serverfee)
                    font.family: FixedFont
                }
                Label {
                    text: Config.baseUnit
                    color: Material.accentColor
                }
                Label {
                    text: swaphelper.serverfeeperc
                        ? '(' + swaphelper.serverfeeperc + ')'
                        : ''
                }
            }

            Label {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                text: qsTr('Mining fee')
                color: Material.accentColor
            }

            RowLayout {
                Layout.preferredWidth: 1
                Layout.fillWidth: true
                Label {
                    text: Config.formatSats(swaphelper.miningfee)
                    font.family: FixedFont
                }
                Label {
                    Layout.fillWidth: true
                    text: Config.baseUnit
                    color: Material.accentColor
                }
            }
        }

        Slider {
            id: swapslider
            Layout.topMargin: constants.paddingLarge
            Layout.bottomMargin: constants.paddingLarge
            Layout.leftMargin: constants.paddingXXLarge + (parent.width - 2 * constants.paddingXXLarge) * swaphelper.leftVoid
            Layout.rightMargin: constants.paddingXXLarge + (parent.width - 2 * constants.paddingXXLarge) * swaphelper.rightVoid

            Layout.fillWidth: true

            background: Rectangle {
                x: swapslider.leftPadding
                y: swapslider.topPadding + swapslider.availableHeight / 2 - height / 2
                implicitWidth: 200
                implicitHeight: 4
                width: swapslider.availableWidth
                height: implicitHeight
                radius: 2
                color: Color.transparent(control.Material.accentColor, 0.33)

                // full width somehow misaligns with handle, define rangeWidth
                property int rangeWidth: width - swapslider.leftPadding

                Rectangle {
                    x: swapslider.visualPosition > swapslider.scenter
                        ? swapslider.scenter * parent.rangeWidth
                        : swapslider.visualPosition * parent.rangeWidth
                    width: swapslider.visualPosition > swapslider.scenter
                        ? (swapslider.visualPosition-swapslider.scenter) * parent.rangeWidth
                        : (swapslider.scenter-swapslider.visualPosition) * parent.rangeWidth
                    height: parent.height
                    color: Material.accentColor
                    radius: 2
                }

                Rectangle {
                    x: swapslider.scenter * parent.rangeWidth
                    y: -4
                    width: 1
                    height: parent.height + 2*4
                    color: parent.color
                }
            }

            property real scenter: -swapslider.from/(swapslider.to-swapslider.from)

            from: swaphelper.rangeMin
            to: swaphelper.rangeMax

            onValueChanged: {
                if (activeFocus)
                    swaphelper.sliderPos = value
            }
        }

        InfoTextArea {
            Layout.leftMargin: constants.paddingXXLarge
            Layout.rightMargin: constants.paddingXXLarge
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignHCenter
            visible: swaphelper.userinfo != ''
            text: swaphelper.userinfo
        }

        Item { Layout.fillHeight: true; Layout.preferredWidth: 1 }

        FlatButton {
            Layout.columnSpan: 2
            Layout.fillWidth: true
            text: qsTr('Ok')
            icon.source: Qt.resolvedUrl('../../icons/confirmed.png')
            enabled: swaphelper.valid
            onClicked: swaphelper.executeSwap()
        }
    }

    Connections {
        target: swaphelper
        function onSliderPosChanged() {
            swapslider.value = swaphelper.sliderPos
        }
        function onSwapSuccess() {
            root.close()
        }
    }

    Component.onCompleted: {
        swapslider.value = swaphelper.sliderPos
    }

}
