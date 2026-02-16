// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick 2.15
import QtQuick.Layouts 1.15
import HelperWidgets 2.0
import StudioTheme 1.0 as StudioTheme

Section {
    caption: qsTr("Shader")
    width: parent.width

    SectionLayout {
        PropertyLabel {
            text: qsTr("Source")
            tooltip: qsTr("Sets the shader source code.")
        }

        SecondColumnLayout {
            UrlChooser {
                backendValue: backendValues.shader
                filter: "*.vert *.frag *.glslv *.glslf *.glsl *.vsh *.fsh"
            }

            ExpandingSpacer {}
        }

        PropertyLabel {
            text: qsTr("Stage")
            tooltip: qsTr("Sets the shader stage.")
        }

        SecondColumnLayout {
            ComboBox {
                scope: "Shader"
                model: ["Vertex", "Fragment"]
                backendValue: backendValues.stage
                implicitWidth: StudioTheme.Values.singleControlColumnWidth
                               + StudioTheme.Values.actionIndicatorWidth
            }

            ExpandingSpacer {}
        }
    }
}
