// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property TextureInput noiseSample: TextureInput {
        texture: Texture {
            tilingModeHorizontal: Texture.Repeat
            tilingModeVertical: Texture.Repeat
            source: "qrc:/qtquick3deffects/maps/brushnoise.png"
        }
    }
    property real amount: 10.0      // 0 - 127
    property int direction: 0       // 0 = both, 1 = horizontal, 2 = vertical
    property bool randomize: true

    Shader {
        id: scatter
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/scatter.frag"
    }

    passes: [
        Pass {
            shaders: [ scatter ]
        }
    ]
}
