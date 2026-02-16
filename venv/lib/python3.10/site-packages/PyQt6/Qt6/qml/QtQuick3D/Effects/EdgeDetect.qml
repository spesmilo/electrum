// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property real edgeStrength: 0.5 // 0 - 1

    Shader {
        id: edgeVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/edgedetect.vert"
    }

    Shader {
        id: edgeFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/edgedetect.frag"
    }

    passes: [
        Pass {
            shaders: [ edgeVert, edgeFrag ]
        }
    ]
}
