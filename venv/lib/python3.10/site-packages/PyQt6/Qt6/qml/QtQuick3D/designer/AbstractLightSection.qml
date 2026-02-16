// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        caption: qsTr("Light")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Color")
                tooltip: qsTr("Sets the color applied to models illuminated by this light.")
            }

            ColorEditor {
                backendValue: backendValues.color
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Ambient Color")
                tooltip: qsTr("Sets the ambient color applied to materials before being lit by this light.")
            }

            ColorEditor {
                backendValue: backendValues.ambientColor
                supportGradient: false
            }

            PropertyLabel {
                text: qsTr("Brightness")
                tooltip: qsTr("Sets an overall multiplier for this light’s effects.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 9999999
                    decimals: 2
                    stepSize: 0.01
                    backendValue: backendValues.brightness
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Scope")
                tooltip: qsTr("Sets a Node in the scene to be the scope of this light. Only that node and it's children are affected by this light.")
            }

            SecondColumnLayout {
                ItemFilterComboBox {
                    typeFilter: "QtQuick3D.Node"
                    backendValue: backendValues.scope
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Bake Mode")
                tooltip: qsTr("Controls if the light is active in baked lighting, such as when generating lightmaps.")
            }

            SecondColumnLayout {
                ComboBox {
                    scope: "Light"
                    model: ["BakeModeDisabled", "BakeModeIndirect", "BakeModeAll"]
                    backendValue: backendValues.bakeMode
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

        }
    }

    ShadowSection {
        width: parent.width
    }

    NodeSection {
        width: parent.width
    }
}
