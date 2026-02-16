// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        caption: qsTr("Curve")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Shoulder Slope")
                tooltip: qsTr("Set the slope of the curve shoulder.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 3
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.shoulderSlope
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Shoulder Emphasis")
                tooltip: qsTr("Set the emphasis of the curve shoulder.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -1
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.shoulderEmphasis
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Toe Slope")
                tooltip: qsTr("Set the slope of the curve toe.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 3
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.toeSlope
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Toe Emphasis")
                tooltip: qsTr("Set the emphasis of the curve toe.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -1
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.toeEmphasis
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        caption: qsTr("Color")
        width: parent.width

        SectionLayout {
            PropertyLabel {
                text: qsTr("Contrast Boost")
                tooltip: qsTr("Set the contrast boost amount.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: -1
                    maximumValue: 2
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.contrastBoost
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Saturation Level")
                tooltip: qsTr("Set the color saturation level.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0
                    maximumValue: 2
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.saturationLevel
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Gamma")
                tooltip: qsTr("Set the gamma value.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0.1
                    maximumValue: 8
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.gammaValue
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Use Exposure")
                tooltip: qsTr("Specifies if the exposure or white point should be used.")
            }

            SecondColumnLayout {
                CheckBox {
                    text: backendValues.useExposure.valueToString
                    backendValue: backendValues.useExposure
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("White Point")
                tooltip: qsTr("Set the white point value.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0.01
                    maximumValue: 128
                    decimals: 2
                    backendValue: backendValues.whitePoint
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Exposure")
                tooltip: qsTr("Set the exposure value.")
            }

            SecondColumnLayout {
                SpinBox {
                    minimumValue: 0.01
                    maximumValue: 16
                    decimals: 2
                    backendValue: backendValues.exposureValue
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }
}
