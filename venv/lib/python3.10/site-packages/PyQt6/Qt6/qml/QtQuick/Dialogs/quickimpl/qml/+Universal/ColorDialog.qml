// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
// Qt-Security score:significant reason:default

import QtQuick
import QtQuick.Controls.Universal
import QtQuick.Controls.Universal.impl
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

    padding: 24
    verticalPadding: 18

    standardButtons: T.Dialog.Ok | T.Dialog.Cancel

    isHsl: true

    ColorDialogImpl.eyeDropperButton: eyeDropperButton
    ColorDialogImpl.buttonBox: buttonBox
    ColorDialogImpl.colorPicker: colorPicker
    ColorDialogImpl.alphaSlider: alphaSlider
    ColorDialogImpl.colorInputs: inputs

    background: Rectangle {
        implicitWidth: 200
        implicitHeight: 600
        color: control.Universal.chromeMediumLowColor
        border.color: control.Universal.chromeHighColor
        border.width: 1 // FlyoutBorderThemeThickness
    }

    header: RowLayout {
        spacing: 12

        Label {
            objectName: "titleLabel"
            text: control.title
            elide: Label.ElideRight
            // TODO: QPlatformTheme::TitleBarFont
            font.pixelSize: 20
            visible: parent.parent?.parent === Overlay.overlay
            background: Rectangle {
                x: 1; y: 1 // // FlyoutBorderThemeThickness
                color: control.Universal.chromeMediumLowColor
                width: parent.width - 2
                height: parent.height - 1
            }

            Layout.topMargin: 24
            Layout.bottomMargin: 24
            Layout.leftMargin: 18
            Layout.fillWidth: true
            Layout.preferredWidth: control.title.length > 0 ? implicitHeight : 0
            Layout.preferredHeight: control.title.length > 0 ? implicitHeight : 15
        }

        Button {
            id: eyeDropperButton
            objectName: "eyeDropperButton"
            icon.source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/eye-dropper.png"
            flat: true
            topPadding: 24
            bottomPadding: 24
            visible: false

            Layout.alignment: Qt.AlignRight
            Layout.rightMargin: 18

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
        spacing: 24

        Label {
            text: qsTr("Color")

            Layout.topMargin: 6
            Layout.leftMargin: 24
            Layout.bottomMargin: 24
        }

        Rectangle {
            implicitWidth: 56
            implicitHeight: 36
            border.width: 2
            border.color: control.palette.dark
            color: "transparent"

            Image {
                anchors.fill: parent
                anchors.margins: 6
                source: "qrc:/qt-project.org/imports/QtQuick/Dialogs/quickimpl/images/checkers.png"
                fillMode: Image.Tile
            }

            Rectangle {
                anchors.fill: parent
                anchors.margins: 6
                color: control.color
            }

            Layout.topMargin: 6
            Layout.bottomMargin: 24
        }

        Item {
            Layout.fillWidth: true
        }

        DialogButtonBox {
            id: buttonBox
            standardButtons: control.standardButtons
            spacing: 12
            horizontalPadding: 0

            Layout.rightMargin: 24
            Layout.alignment: Qt.AlignRight
        }
    }

    Overlay.modal: Rectangle {
        color: control.Universal.baseLowColor
    }

    Overlay.modeless: Rectangle {
        color: control.Universal.baseLowColor
    }
}
