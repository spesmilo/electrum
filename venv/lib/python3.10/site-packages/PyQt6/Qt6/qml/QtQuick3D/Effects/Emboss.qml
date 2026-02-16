// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property real amount: 0.003 // 0 - 0.01

    Shader {
        id: emboss
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/emboss.frag"
    }

    passes: [
        Pass {
            shaders: [ emboss ]
        }
    ]
}
