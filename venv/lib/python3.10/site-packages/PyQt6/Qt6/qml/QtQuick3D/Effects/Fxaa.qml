// Copyright (C) 2020 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D

Effect {
    readonly property TextureInput sprite: TextureInput {
        texture: Texture {}
    }

    Shader {
        id: rgbl
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/fxaaRgbl.frag"
    }
    Shader {
        id: blur
        stage: Shader.Fragment
        shader: "qrc:/qtquick3deffects/shaders/fxaaBlur.frag"
    }
    Buffer {
        id: rgblBuffer
        name: "rgbl_buffer"
        format: Buffer.RGBA8
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None // aka frame
    }

    passes: [
        Pass {
            shaders: [ rgbl ]
            output: rgblBuffer
        },
        Pass {
            shaders: [ blur ]
            commands: [
                // INPUT is the texture for rgblBuffer
                BufferInput {
                    buffer: rgblBuffer
                },
                // the actual input texture is exposed as sprite
                BufferInput {
                    sampler: "sprite"
                }
            ]
        }
    ]
}
