// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Column {
    width: parent.width

    Section {
        width: parent.width
        caption: qsTr("Visibility")

        SectionLayout {
            PropertyLabel {
                text: qsTr("Visibility")
                tooltip: qsTr("Sets the local visibility of the node.")
            }

            SecondColumnLayout {
                // ### should be a slider
                CheckBox {
                    text: qsTr("Visible")
                    backendValue: backendValues.visible
                    implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }

            PropertyLabel {
                text: qsTr("Opacity")
                tooltip: qsTr("Sets the local opacity value of the node.")
            }

            SecondColumnLayout {
                // ### should be a slider
                SpinBox {
                    minimumValue: 0
                    maximumValue: 1
                    decimals: 2
                    stepSize: 0.1
                    backendValue: backendValues.opacity
                    sliderIndicatorVisible: true
                    implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                   + StudioTheme.Values.actionIndicatorWidth
                }

                ExpandingSpacer {}
            }
        }
    }

    Section {
        id: transformSection
        width: parent.width
        caption: qsTr("Transform")

        ColumnLayout {
            spacing: StudioTheme.Values.transform3DSectionSpacing

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Translation")
                    tooltip: qsTr("Sets the translation of the node.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "X"
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Y"
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Z"
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
            }

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Rotation")
                    tooltip: qsTr("Sets the rotation of the node in degrees.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.eulerRotation_x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "X"
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.eulerRotation_y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Y"
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.eulerRotation_z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Z"
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
            }

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Scale")
                    tooltip: qsTr("Sets the scale of the node.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.scale_x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "X"
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.scale_y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Y"
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.scale_z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Z"
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
            }

            SectionLayout {
                PropertyLabel {
                    text: qsTr("Pivot")
                    tooltip: qsTr("Sets the pivot of the node.")
                }

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.pivot_x
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "X"
                        color: StudioTheme.Values.theme3DAxisXColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.pivot_y
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Y"
                        color: StudioTheme.Values.theme3DAxisYColor
                    }

                    ExpandingSpacer {}
                }

                PropertyLabel {}

                SecondColumnLayout {
                    SpinBox {
                        minimumValue: -9999999
                        maximumValue: 9999999
                        decimals: 2
                        backendValue: backendValues.pivot_z
                        implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                       + StudioTheme.Values.actionIndicatorWidth
                    }

                    Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

                    ControlLabel {
                        text: "Z"
                        color: StudioTheme.Values.theme3DAxisZColor
                    }

                    ExpandingSpacer {}
                }
            }
        }
    }
}
