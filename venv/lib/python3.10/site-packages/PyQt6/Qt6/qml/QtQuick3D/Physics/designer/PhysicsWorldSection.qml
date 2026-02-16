// Copyright (C) 2023 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Physics World")
    width: parent.width

    SectionLayout {
        // Q_PROPERTY(QQuick3DNode *scene
        PropertyLabel {
            text: qsTr("Scene")
            tooltip: qsTr("The scene node to which the physics world is attached.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Node"
                backendValue: backendValues.scene
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(QQuick3DNode *viewport
        PropertyLabel {
            text: qsTr("Viewport")
            tooltip: qsTr("The node to which the debug geometry of the physics world is added.")
        }

        SecondColumnLayout {
            ItemFilterComboBox {
                typeFilter: "QtQuick3D.Node"
                backendValue: backendValues.viewport
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(bool running)
        PropertyLabel {
            text: qsTr("Running")
            tooltip: qsTr("Whether the physics world is running.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.running.valueToString
                backendValue: backendValues.running
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(bool forceDebugDraw
        PropertyLabel {
            text: qsTr("Force Debug Draw")
            tooltip: qsTr("Whether to force debug drawing of the physics world.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.forceDebugDraw.valueToString
                backendValue: backendValues.forceDebugDraw
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(bool enableCCD
        PropertyLabel {
            text: qsTr("CCD")
            tooltip: qsTr("Whether to enable continuous collision detection.")
        }

        SecondColumnLayout {
            CheckBox {
                text: backendValues.enableCCD.valueToString
                backendValue: backendValues.enableCCD
                implicitWidth: StudioTheme.Values.twoControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(QVector3D gravity)
        PropertyLabel {
            text: qsTr("Gravity")
            tooltip: qsTr("The gravity vector.")
        }

        SecondColumnLayout {
            SpinBox {
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.gravity_x
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "X"
                color: StudioTheme.Values.theme3DAxisXColor
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
        }

        SecondColumnLayout {
            SpinBox {
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.gravity_y
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "Y"
                color: StudioTheme.Values.theme3DAxisYColor
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
        }

        SecondColumnLayout {
            SpinBox {
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 2
                backendValue: backendValues.gravity_z
            }

            Spacer { implicitWidth: StudioTheme.Values.controlLabelGap }

            ControlLabel {
                text: "Z"
                color: StudioTheme.Values.theme3DAxisZColor
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(float typicalLength)
        PropertyLabel {
            text: qsTr("Typical Length")
            tooltip: qsTr("The typical length of objects in the scene.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0.00001
                maximumValue: 9999999
                decimals: 5
                backendValue: backendValues.typicalLength
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(float typicalSpeed
        PropertyLabel {
            text: qsTr("Typical Speed")
            tooltip: qsTr("The typical speed of objects in the scene.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0.00001
                maximumValue: 9999999
                decimals: 5
                backendValue: backendValues.typicalSpeed
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(float defaultDensity)
        PropertyLabel {
            text: qsTr("Default Density")
            tooltip: qsTr("The default density of objects in the scene.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0.00001
                maximumValue: 9999999
                decimals: 5
                backendValue: backendValues.defaultDensity
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(float minimumTimestep)
        PropertyLabel {
            text: qsTr("Min Timestep")
            tooltip: qsTr("Defines the minimum simulation timestep in milliseconds.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0.001
                maximumValue: 9999999
                decimals: 3
                backendValue: backendValues.minimumTimestep
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        // Q_PROPERTY(float maximumTimestep)
        PropertyLabel {
            text: qsTr("Max Timestep")
            tooltip: qsTr("Defines the maximum simulation timestep in milliseconds.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 0.001
                maximumValue: 9999999
                decimals: 3
                backendValue: backendValues.maximumTimestep
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                                + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
