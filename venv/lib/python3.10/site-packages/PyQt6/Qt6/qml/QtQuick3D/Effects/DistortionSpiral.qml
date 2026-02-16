// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property real radius: 0.25              // 0 - 1
    property real distortionStrength: 1.0   // -10 - 10
    property vector2d center: Qt.vector2d(0.5, 0.5)

    Shader {
        id: distortionVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/distortion.vert"
    }

    Shader {
        id: distortionFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/distortionspiral.frag"
    }

    passes: [
        Pass {
            shaders: [ distortionVert, distortionFrag ]
        }
    ]
}
