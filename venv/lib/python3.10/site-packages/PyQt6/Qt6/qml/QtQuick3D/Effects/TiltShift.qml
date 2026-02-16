// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    readonly property TextureInput sourceSampler: TextureInput {
        texture: Texture {}
    }
    property real focusPosition: 0.5    // 0 - 1
    property real focusWidth: 0.2       // 0 - 1
    property real blurAmount: 4         // 0 - 10
    property bool isVertical: false
    property bool isInverted: false

    Shader {
        id: downsampleVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/downsample.vert"
    }
    Shader {
        id: downsampleFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/downsampletiltshift.frag"
    }

    Shader {
        id: blurVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3deffects/shaders/poissonblurtiltshift.vert"
    }
    Shader {
        id: blurFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/poissonblurtiltshift.frag"
    }

    Buffer {
        id: downsampleBuffer
        name: "downsampleBuffer"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }

    passes: [
        Pass {
            shaders: [ downsampleVert, downsampleFrag ]
            output: downsampleBuffer
        },
        Pass {
            shaders: [ blurVert, blurFrag ]
            commands: [
                // INPUT is the texture for downsampleBuffer
                BufferInput {
                    buffer: downsampleBuffer
                },
                // the pass' input texture is exposed as sourceSampler
                BufferInput {
                    sampler: "sourceSampler"
                }
            ]
        }
    ]
}
