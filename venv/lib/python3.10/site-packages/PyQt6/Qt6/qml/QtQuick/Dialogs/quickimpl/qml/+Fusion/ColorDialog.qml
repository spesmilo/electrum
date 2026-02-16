// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Fusion
import QtQuick.Controls.Fusion.impl
import QtQuick.Dialogs
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts
import QtQuick.Templates as T

ColorDialogImpl {
    id: control

    implicitWidth: Math.max(implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            implicitHeaderWidth,
                            implicitFooterWidth)
    implicitHeight: Math.max(implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding
                             + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
                             + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0))

    padding: 6
    horizontalPadding: 12

    isHsl: true

    standardButtons: T.Dialog.Ok | T.Dialog.Cancel

    ColorDialogImpl.eyeDropperButton: eyeDropperButton
    ColorDialogImpl.buttonBox: buttonBox
    ColorDialogImpl.colorPicker: colorPicker
    ColorDialogImpl.colorInputs: inputs
    ColorDialogImpl.alphaSlider: alphaSlider

    background: Rectangle {
        implicitWidth: 200
        implicitHeight: 400
        color: control.palette.window
        border.color: control.palette.mid
        radius: 2

        Rectangle {
            z: -1
            x: 1
            y: 1
            width: parent.width
            height: parent.height
            color: control.palette.shadow
            opacity: 0.2
            radius: 2
        }
    }

    header: RowLayout {
        Label {
            objectName: "titleLabel"
            text: control.title
            elide: Label.ElideRight
            font.bold: true
            padding: 6
            visible: parent.parent?.parent === Overlay.overlay

            Layout.preferredWidth: control.title.length > 0 ? implicitWidth : 0
            Layout.preferredHeight: control.title.length > 0 ? implicitHeight : 15
            Layout.leftMargin: 12
            Layout.alignment: Qt.AlignLeft
        }
        Button {
            id: eyeDropperButton
            objectName: "eyeDropperButton"
            icon.source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/eye-dropper.png"
            flat: true
            visible: false

            Layout.preferredWidth: implicitHeight
            Layout.alignment: Qt.AlignRight
            Layout.rightMargin: 6

            Accessible.name: qsTr("Eye dropper")
        }
    }

    contentItem: ColumnLayout {
        spacing: 12
        SaturationLightnessPicker {
            id: colorPicker
            objectName: "colorPicker"
            color: control.color

            Layout.fillWidth: true
            Layout.fillHeight: true
        }

        Slider {
            id: hueSlider
            objectName: "hueSlider"
            orientation: Qt.Horizontal
            value: control.hue
            implicitHeight: 20
            onMoved: function() { control.hue = value; }
            handle: PickerHandle {
                x: hueSlider.leftPadding + (hueSlider.horizontal
                    ? hueSlider.visualPosition * (hueSlider.availableWidth - width)
                    : (hueSlider.availableWidth - width) / 2)
                y: hueSlider.topPadding + (hueSlider.horizontal
                    ? (hueSlider.availableHeight - height) / 2
                    : hueSlider.visualPosition * (hueSlider.availableHeight - height))
                picker: hueSlider
            }
            background: Rectangle {
                anchors.fill: parent
                anchors.leftMargin: hueSlider.handle.width / 2
                anchors.rightMargin: hueSlider.handle.width / 2
                border.width: 2
                border.color: control.palette.dark
                radius: 10
                color: "transparent"
                Rectangle {
                    anchors.fill: parent
                    anchors.margins: 4
                    radius: 10
                    gradient: HueGradient {
                        orientation: Gradient.Horizontal
                    }
                }
            }

            Accessible.name: qsTr("Hue")

            Layout.fillWidth: true
            Layout.leftMargin: 12
            Layout.rightMargin: 12
        }

        Slider {
            id: alphaSlider
            objectName: "alphaSlider"
            orientation: Qt.Horizontal
            value: control.alpha
            implicitHeight: 20
            handle: PickerHandle {
                x: alphaSlider.leftPadding + (alphaSlider.horizontal
                    ? alphaSlider.visualPosition * (alphaSlider.availableWidth - width)
                    : (alphaSlider.availableWidth - width) / 2)
                y: alphaSlider.topPadding + (alphaSlider.horizontal
                    ? (alphaSlider.availableHeight - height) / 2
                    : alphaSlider.visualPosition * (alphaSlider.availableHeight - height))
                picker: alphaSlider
            }
            background: Rectangle {
                anchors.fill: parent
                anchors.leftMargin: parent.handle.width / 2
                anchors.rightMargin: parent.handle.width / 2
                border.width: 2
                border.color: control.palette.dark
                radius: 10
                color: "transparent"

                Image {
                    anchors.fill: alphaSliderGradient
                    source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/checkers.png"
                    fillMode: Image.Tile
                }

                Rectangle {
                    id: alphaSliderGradient
                    anchors.fill: parent
                    anchors.margins: 4
                    radius: 10
                    gradient: Gradient {
                        orientation: Gradient.Horizontal
                        GradientStop {
                            position: 0
                            color: "transparent"
                        }
                        GradientStop {
                            position: 1
                            color: Qt.rgba(control.color.r, control.color.g, control.color.b, 1)
                        }
                    }
                }
            }

            Accessible.name: qsTr("Alpha")

            Layout.fillWidth: true
            Layout.leftMargin: 12
            Layout.rightMargin: 12
        }

        ColorInputs {
            id: inputs
            color: control.color
            Layout.fillWidth: true
            Layout.leftMargin: 12
            Layout.rightMargin: 12
            Layout.bottomMargin: 12
        }
    }

    footer: RowLayout {
        spacing: 12

        Label {
            text: qsTr("Color")

            Layout.leftMargin: 12
            Layout.topMargin: 6
            Layout.bottomMargin: 6
        }

        Rectangle {
            implicitWidth: (parent.height - 24) * 2
            implicitHeight: implicitWidth / 2
            color: "transparent"

            Image {
                anchors.fill: parent
                source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/checkers.png"
                fillMode: Image.Tile
            }

            Rectangle {
                anchors.fill: parent
                color: control.color
            }

            Layout.topMargin: 6
            Layout.bottomMargin: 6
        }

        Item {
            Layout.fillWidth: true
            Layout.topMargin: 6
            Layout.bottomMargin: 6
        }

        DialogButtonBox {
            id: buttonBox
            standardButtons: control.standardButtons
            spacing: 6
            horizontalPadding: 0
            verticalPadding: 0

            Layout.rightMargin: 12
            Layout.topMargin: 6
            Layout.bottomMargin: 6
        }
    }

    T.Overlay.modal: Rectangle {
        color: Fusion.topShadow
    }

    T.Overlay.modeless: Rectangle {
        color: Fusion.topShadow
    }
}
