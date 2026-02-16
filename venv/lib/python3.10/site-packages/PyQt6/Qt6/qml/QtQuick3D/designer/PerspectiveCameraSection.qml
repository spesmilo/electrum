// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Perspective Camera")

    SectionLayout {
        PropertyLabel {
            text: qsTr("Clip Near")
            tooltip: qsTr("Sets the near value of the view frustum of the camera.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 0
                backendValue: backendValues.clipNear
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Clip Far")
            tooltip: qsTr("Sets the far value of the view frustum of the camera.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: -9999999
                maximumValue: 9999999
                decimals: 0
                stepSize: 100
                backendValue: backendValues.clipFar
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Field of View")
            tooltip: qsTr("Sets the field of view of the camera in degrees.")
        }

        SecondColumnLayout {
            SpinBox {
                minimumValue: 1
                maximumValue: 180
                decimals: 2
                backendValue: backendValues.fieldOfView
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("FOV Orientation")
            tooltip: qsTr("Sets if the field of view property reflects the vertical or the horizontal field of view.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "PerspectiveCamera"
                model: ["Vertical", "Horizontal"]
                backendValue: backendValues.fieldOfViewOrientation
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
