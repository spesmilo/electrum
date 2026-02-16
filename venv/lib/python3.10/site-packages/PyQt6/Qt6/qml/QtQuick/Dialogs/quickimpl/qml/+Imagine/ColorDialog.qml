// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.impl
import QtQuick.Controls.Imagine
import QtQuick.Controls.Imagine.impl
import QtQuick.Dialogs.quickimpl
import QtQuick.Layouts
import QtQuick.Templates as T

ColorDialogImpl {
    id: control

    // Can't set implicitWidth of the NinePatchImage background, so we do it here.
    implicitWidth: Math.max(200,
                            implicitBackgroundWidth + leftInset + rightInset,
                            implicitContentWidth + leftPadding + rightPadding,
                            implicitHeaderWidth,
                            implicitFooterWidth)
    implicitHeight: Math.max(600,
                             implicitBackgroundHeight + topInset + bottomInset,
                             implicitContentHeight + topPadding + bottomPadding
                             + (implicitHeaderHeight > 0 ? implicitHeaderHeight + spacing : 0)
                             + (implicitFooterHeight > 0 ? implicitFooterHeight + spacing : 0))

    topPadding: background ? background.topPadding : 0
    leftPadding: background ? background.leftPadding : 0
    rightPadding: background ? background.rightPadding : 0
    bottomPadding: background ? background.bottomPadding : 0

    topInset: background ? -background.topInset || 0 : 0
    leftInset: background ? -background.leftInset || 0 : 0
    rightInset: background ? -background.rightInset || 0 : 0
    bottomInset: background ? -background.bottomInset || 0 : 0

    standardButtons: T.Dialog.Ok | T.Dialog.Cancel

    isHsl: true

    ColorDialogImpl.eyeDropperButton: eyeDropperButton
    ColorDialogImpl.buttonBox: buttonBox
    ColorDialogImpl.colorPicker: colorPicker
    ColorDialogImpl.alphaSlider: alphaSlider
    ColorDialogImpl.colorInputs: inputs

    background: NinePatchImage {
        source: Imagine.url + "dialog-background"
        NinePatchImageSelector on source {
            states: [
                {"modal": control.modal},
                {"dim": control.dim}
            ]
        }
    }

    header: RowLayout {
        Label {
            objectName: "titleLabel"
            text: control.title
            elide: Label.ElideRight
            font.bold: true
            font.pixelSize: 16
            leftPadding: 16
            rightPadding: 16
            topPadding: 16
            bottomPadding: 16
            visible: parent.parent?.parent === Overlay.overlay

            Layout.preferredWidth: control.title.length > 0 ? implicitWidth : 0
            Layout.preferredHeight: control.title.length > 0 ? implicitHeight : 15
         }

        Button {
            id: eyeDropperButton
            objectName: "eyeDropperButton"
            icon.source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/eye-dropper.png"
            flat: true
            topPadding: 16
            bottomPadding: 16
            visible: false

            Layout.alignment: Qt.AlignRight
            Layout.rightMargin: 16

            Accessible.name: qsTr("Eye dropper")
        }
    }

    contentItem: ColumnLayout {
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
            onMoved: function() { control.hue = value; }

            Accessible.name: qsTr("Hue")

            Layout.fillWidth: true
            Layout.leftMargin: 16
            Layout.rightMargin: 16

            handle: PickerHandle {
                x: hueSlider.leftPadding + (hueSlider.horizontal
                    ? hueSlider.visualPosition * (hueSlider.availableWidth - width)
                    : (hueSlider.availableWidth - width) / 2)
                y: hueSlider.topPadding + (hueSlider.horizontal
                    ? (hueSlider.availableHeight - height) / 2
                    : hueSlider.visualPosition * (hueSlider.availableHeight - height))
                picker: hueSlider
            }

            implicitHeight: 20

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
                            color: Qt.rgba(control.color.r,
                                           control.color.g,
                                           control.color.b,
                                           1)
                        }
                    }
                }
            }

            Accessible.name: qsTr("Alpha")

            Layout.fillWidth: true
            Layout.leftMargin: 16
            Layout.rightMargin: 16
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
        spacing: 20

        Label {
            text: qsTr("Color")

            Layout.leftMargin: 16
            Layout.bottomMargin: 16
        }

        Rectangle {
            implicitWidth: 32
            implicitHeight: 32
            border.width: 2
            border.color: control.palette.dark
            color: "transparent"

            Image {
                anchors.fill: parent
                anchors.margins: 4
                source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/checkers.png"
                fillMode: Image.Tile
            }

            Rectangle {
                anchors.fill: parent
                anchors.margins: 4
                color: control.color
            }

            Layout.bottomMargin: 16
        }

        Item {
            // empty filler
            Layout.fillWidth: true
        }

        DialogButtonBox {
            id: buttonBox
            standardButtons: control.standardButtons
            spacing: 12

            Layout.bottomMargin: 16
            Layout.rightMargin: 16
            Layout.alignment: Qt.AlignRight
        }
    }


    T.Overlay.modal: NinePatchImage {
        source: Imagine.url + "dialog-overlay"
        NinePatchImageSelector on source {
            states: [
                {"modal": true}
            ]
        }
    }

    T.Overlay.modeless: NinePatchImage {
        source: Imagine.url + "dialog-overlay"
        NinePatchImageSelector on source {
            states: [
                {"modal": false}
            ]
        }
    }
}
