// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Sprite Particle")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Blend Mode")
            tooltip: qsTr("Sets the blending mode used for rendering the particles.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "SpriteParticle3D"
                model: ["SourceOver", "Screen", "Multiply"]
                backendValue: backendValues.blendMode
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Casts Reflections")
            tooltip: qsTr("Enables reflection probes to reflect sprite particles.")
        }

        SecondColumnLayout {
            CheckBox {
                id: castsReflectionsCheckBox
                text: backendValues.castsReflections.valueToString
                backendValue: backendValues.castsReflections
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Sprite")
            tooltip: qsTr("Sets the Texture used for the particles.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Texture"
                backendValue: backendValues.sprite
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Sprite Sequence")
            tooltip: qsTr("Sets the sprite sequence properties for the particle.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Particles3D.SpriteSequence3D"
                backendValue: backendValues.spriteSequence
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Billboard")
            tooltip: qsTr("Sets if the particle texture should always be aligned face towards the screen.")
        }

        SecondColumnLayout {
            CheckBox {
                id: billboardCheckBox
                text: backendValues.billboard.valueToString
                backendValue: backendValues.billboard
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Particle Scale")
            tooltip: qsTr("Sets the scale multiplier of the particles.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -999999
                maximumValue: 999999
                decimals: 2
                backendValue: backendValues.particleScale
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Color Table")
            tooltip: qsTr("Sets the Texture used for coloring the particles.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Texture"
                backendValue: backendValues.colorTable
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Lights")
            tooltip: qsTr("Sets the lights used for the particles.")
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 5
        }

        SecondColumnLayout {
            EditableListView {
                backendValue: backendValues.lights
                model: backendValues.lights.expressionAsList
                Layout.fillWidth: true
                typeFilter: "QtQuick3D.Light"
                onAdd: function(value) { backendValues.lights.idListAdd(value) }
                onRemove: function(idx) { backendValues.lights.idListRemove(idx) }
                onReplace: function (idx, value) { backendValues.lights.idListReplace(idx, value) }
            }
            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Offset")
        }

        SecondColumnLayout {
            SpinBox {
                maximumValue: 999999
                minimumValue: -999999
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.offsetX
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "X"
                tooltip: qsTr("Offsets the X coordinate.")
            }

            Spacer { implicitWidth: StudioTheme.Values.controlGap }

            SpinBox {
                maximumValue: 999999
                minimumValue: -999999
                decimals: 2
                stepSize: 0.1
                backendValue: backendValues.offsetY
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "Y"
                tooltip: qsTr("Offsets the Y coordinate.")
            }

            ExpandingSpacer {}
        }
    }
}
