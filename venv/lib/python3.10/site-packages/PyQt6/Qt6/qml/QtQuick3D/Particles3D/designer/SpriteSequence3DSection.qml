// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Particle Sprite Sequence")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Frame Count")
            tooltip: qsTr("Sets the amount of image frames in sprite.")
        }
        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 0
                backendValue: backendValues.frameCount
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Frame Index")
            tooltip: qsTr("Sets the initial index of the frame.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0
                maximumValue: 999999
                decimals: 0
                backendValue: backendValues.frameIndex
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Interpolate")
            tooltip: qsTr("Sets if the sprites are interpolated (blended) between frames to make the animation appear smoother.")
        }

        SecondColumnLayout {
            CheckBox {
                id: interpolateCheckBox
                text: backendValues.interpolate.valueToString
                backendValue: backendValues.interpolate
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Duration")
            tooltip: qsTr("Sets the duration in milliseconds how long it takes for the sprite sequence to animate.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -1
                maximumValue: 999999
                decimals: 0
                backendValue: backendValues.duration
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Duration Variation")
            tooltip: qsTr("Sets the duration variation in milliseconds.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -999999
                maximumValue: 999999
                decimals: 0
                backendValue: backendValues.durationVariation
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Random Start")
            tooltip: qsTr("Sets if the animation should start from a random frame between 0 and frameCount - 1.")
        }

        SecondColumnLayout {
            CheckBox {
                id: randomStartCheckBox
                text: backendValues.randomStart.valueToString
                backendValue: backendValues.randomStart
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Animation Direction")
            tooltip: qsTr("Sets the animation direction of the sequence.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "SpriteSequence3D"
                model: ["Normal", "Reverse", "Alternate", "AlternateReverse", "SingleFrame"]
                backendValue: backendValues.animationDirection
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
