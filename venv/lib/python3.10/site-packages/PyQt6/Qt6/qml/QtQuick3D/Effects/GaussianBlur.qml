// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    property real amount: 2 // 0 - 10
    Shader {
        id: vertical
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/blurvertical.vert"
    }
    Shader {
        id: horizontal
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/blurhorizontal.vert"
    }
    Shader {
        id: gaussianblur
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/gaussianblur.frag"
    }

    Buffer {
        id: tempBuffer
        name: "tempBuffer"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None // aka frame
    }

    passes: [
        Pass {
            shaders: [ horizontal, gaussianblur ]
            output: tempBuffer
        },
        Pass {
            shaders: [ vertical, gaussianblur ]
            commands: [
                BufferInput {
                    buffer: tempBuffer
                }
            ]
        }
    ]
}
