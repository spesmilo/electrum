// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Helpers.impl

MainSceneEffect {
    id: sceneEffect
    property int tonemapMode: SceneEnvironment.TonemapModeLinear
    property real exposure: 1.0
    property real white: 1.0
    property bool applyFXAA: false
    property bool ditheringEnabled: false
    property real sharpnessAmount: 0.0 // 0.0 - 1.0
    property bool colorAdjustmentsEnabled: false
    property real adjustmentBrightness: 1.0
    property real adjustmentContrast: 1.0
    property real adjustmentSaturation: 1.0

    // Lens Flare
    property bool lensFlareEnabled: false
    property real lensFlareBloomScale: 10           // 0 - 20
    property real lensFlareBloomBias: 0.95          // 0 - x (basically maximum color value)
    property real lensFlareGhostDispersal: 0.5      // 0 - 1
    property int lensFlareGhostCount: 4             // 0 - 20
    property real lensFlareHaloWidth: 0.25          // 0 - 1
    property real lensFlareStretchToAspect: 0.5     // 0 - 1
    property real lensFlareDistortion: 5            // 0.0 - 20.0
    property real lensFlareBlurAmount: 3            // 0.0 - 5.0
    property bool lensFlareApplyDirtTexture: false
    property bool lensFlareApplyStarburstTexture: false
    property vector3d lensFlareCameraDirection: Qt.vector3d(0, 0, -1)
    property bool lensFlareDebug: false

    property TextureInput lensColorTexture: TextureInput {
        id: lensColorTextureInput
        texture: defaultLensColorTexture
    }
    property alias lensColorTextureAlias: lensColorTextureInput.texture
    Texture {
        id: defaultLensColorTexture
        source: "qrc:/qtquick3d_helpers/images/gradientTexture.png"
        tilingModeHorizontal: Texture.ClampToEdge
        tilingModeVertical: Texture.ClampToEdge
    }

    property TextureInput lensDirtTexture: TextureInput {
        id: lensDirtTextureInput
        texture: defaultLensDirtTexture
    }
    property alias lensDirtTextureAlias: lensDirtTextureInput.texture
    Texture {
        id: defaultLensDirtTexture
        source: "qrc:/qtquick3d_helpers/images/lens_dirt_default.jpeg"
    }

    property TextureInput starburstTexture: TextureInput {
        id: lensStarburstTextureInput
        texture: defaultLensStarburstTexture
    }
    property alias starburstTextureAlias: lensStarburstTextureInput.texture
    Texture {
        id: defaultLensStarburstTexture
        source: "qrc:/qtquick3d_helpers/images/noiseTexture.png"
    }

    // Glow data
    readonly property bool isFirstPass: true
    property bool isGlowEnabled: false
    property bool glowQualityHigh: false
    property bool glowUseBicubicUpscale: false
    property real glowStrength : 1.0        // 0.0 - 2.0
    property real glowIntensity : 0.8       // 0.0 - 8.0
    property real glowBloom : 0.0           // 0.0 - 1.0
    property int glowBlendMode : 2          // Additive,Screen,Softlight,Replace
    property real glowHDRMaximumValue: 12.0 // 0.0 - 256.0
    property real glowHDRScale: 2.0         // 0.0 - 4.0
    property real glowHDRMinimumValue: 1.0     // 0.0 - 4.0
    property int glowLevel: 1               // 1 - 7

    // Color Grading (LUT)
    property bool enableLut: false
    property alias lutTextureAlias: lutTextureInput.texture
    property TextureInput lut: TextureInput {
        id: lutTextureInput
        texture: defaultLutTexture
    }
    property real lutSize: 16.0 // size of texture, textures are 3d in 2d, so width = lutSize * lutSize, height = lutSize
    property real lutFilterAlpha: 1.0 // 0.0 - 1.0
    Texture {
        id: defaultLutTexture
        source: "qrc:/qtquick3d_helpers/luts/identity.png"
    }

    // Vignette
    property bool vignetteEnabled: false
    property real vignetteStrength: 15 // 0 - 15
    property color vignetteColor: "gray"
    property real vignetteRadius: 0.35 // 0 - 5

    readonly property TextureInput glowBuffer1: TextureInput {
        texture: Texture {}
    }
    readonly property TextureInput glowBuffer2: TextureInput {
        texture: Texture {}
    }
    readonly property TextureInput glowBuffer3: TextureInput {
        texture: Texture {}
    }
    readonly property TextureInput glowBuffer4: TextureInput {
        texture: Texture {}
    }
    readonly property TextureInput glowBuffer5: TextureInput {
        texture: Texture {}
    }
    readonly property TextureInput glowBuffer6: TextureInput {
        texture: Texture {}
    }
    readonly property TextureInput glowBuffer7: TextureInput {
        texture: Texture {}
    }

    readonly property TextureInput lensFlareDownsampleBuffer: TextureInput {
        texture: Texture {}
    }

    readonly property TextureInput lensFlareFeaturesBuffer: TextureInput {
        texture: Texture {}
    }

    readonly property TextureInput lensFlareTexture: TextureInput {
        texture: Texture {}
    }

    Component.onCompleted: buildPasses()

    onIsGlowEnabledChanged: buildPasses()
    onLensFlareEnabledChanged: buildPasses()

    function buildPasses() {
        let passList = [];
        if (lensFlareEnabled) {
            passList.push(lensFlareDownsamplePass)
            passList.push(lensFlareFeaturesPass)
            passList.push(lensFlareBlurHorizontalPass)
            passList.push(lensFlareBlurVerticalPass)
        }

        if (isGlowEnabled) {
            passList.push(horizontalBlurPass1)
            passList.push(verticalBlurPass1)
            passList.push(horizontalBlurPass2)
            passList.push(verticalBlurPass2)
            passList.push(horizontalBlurPass3)
            passList.push(verticalBlurPass3)
            passList.push(horizontalBlurPass4)
            passList.push(verticalBlurPass4)
            passList.push(horizontalBlurPass5)
            passList.push(verticalBlurPass5)
            passList.push(horizontalBlurPass6)
            passList.push(verticalBlurPass6)
            passList.push(horizontalBlurPass7)
            passList.push(verticalBlurPass7)
        }

        passList.push(tonemapPass)
        tonemapPass.rebuildCommands();

        sceneEffect.passes = passList // qmllint disable read-only-property
    }

    Shader {
        id: tonemapperFrag
        stage: Shader.Fragment
        shader: "qrc:/qtquick3d_helpers/shaders/tonemapper.frag"
    }

    Shader {
        id: glowHorizontalBlur
        stage: Shader.Fragment
        shader: "qrc:/qtquick3d_helpers/shaders/glowhorizontalblur.frag"
    }

    Shader {
        id: glowVerticalBlur
        stage: Shader.Fragment
        shader: "qrc:/qtquick3d_helpers/shaders/glowverticalblur.frag"
    }

    Shader {
        id: lensFlareDownsample
        stage: Shader.Fragment
        shader: "qrc:/qtquick3d_helpers/shaders/lensflaredownsample.frag"
    }

    Shader {
        id: lensFlareFeatures
        stage: Shader.Fragment
        shader: "qrc:/qtquick3d_helpers/shaders/lensflarefeatures.frag"
    }

    Shader {
        id: lensFlareVerticalBlurVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3d_helpers/shaders/lensflareblurvertical.vert"
    }
    Shader {
        id: lensFlareHorizontalVert
        stage: Shader.Vertex
        shader: "qrc:/qtquick3d_helpers/shaders/lensflareblurhorizontal.vert"
    }
    Shader {
        id: lensFlareGaussianBlur
        stage: Shader.Fragment
        shader: "qrc:/qtquick3d_helpers/shaders/lensflaregaussianblur.frag"
    }

    Buffer {
        id: tempBuffer1
        name: "tempBuffer1"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }
    Buffer {
        id: tempBuffer2
        name: "tempBuffer2"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.25
    }
    Buffer {
        id: tempBuffer3
        name: "tempBuffer3"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.125
    }
    Buffer {
        id: tempBuffer4
        name: "tempBuffer4"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.0625
    }
    Buffer {
        id: tempBuffer5
        name: "tempBuffer5"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.03125
    }
    Buffer {
        id: tempBuffer6
        name: "tempBuffer6"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.015625
    }
    Buffer {
        id: tempBuffer7
        name: "tempBuffer7"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.0078125
    }

    Buffer {
        id: glowBuffer1
        name: "glowBuffer1"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }
    Buffer {
        id: glowBuffer2
        name: "glowBuffer2"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.25
    }
    Buffer {
        id: glowBuffer3
        name: "glowBuffer3"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.125
    }
    Buffer {
        id: glowBuffer4
        name: "glowBuffer4"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.0625
    }
    Buffer {
        id: glowBuffer5
        name: "glowBuffer5"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.03125
    }
    Buffer {
        id: glowBuffer6
        name: "glowBuffer6"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.015625
    }
    Buffer {
        id: glowBuffer7
        name: "glowBuffer7"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.0078125
    }

    Buffer {
        id: lensFlareDownsampleBuffer
        name: "lensFlareDownsampleBuffer"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }

    Buffer {
        id: lensFlareFeaturesBuffer
        name: "lensFlareFeaturesBuffer"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }

    Buffer {
        id: lensFlareBlurTempBuffer
        name: "lensFlareBlurTempBuffer"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }

    Buffer {
        id: lensFlareBlurBuffer
        name: "lensFlareBlurBuffer"
        format: Buffer.RGBA16F
        textureFilterOperation: Buffer.Linear
        textureCoordOperation: Buffer.ClampToEdge
        bufferFlags: Buffer.None
        sizeMultiplier: 0.5
    }

    Pass {
        id: horizontalBlurPass1
        shaders: [glowHorizontalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: true
            }
        ]
        output: tempBuffer1
    }

    Pass {
        id: verticalBlurPass1
        shaders: [glowVerticalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: tempBuffer1
            }
        ]
       output: glowBuffer1
    }

    Pass {
        id: horizontalBlurPass2
        shaders: [glowHorizontalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: glowBuffer1
            }
        ]
        output: tempBuffer2
    }

    Pass {
        id: verticalBlurPass2
        shaders: [glowVerticalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: tempBuffer2
            }
        ]
        output: glowBuffer2
    }

    Pass {
        id: horizontalBlurPass3
        shaders: [glowHorizontalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: glowBuffer2
            }
        ]
        output: tempBuffer3
    }

    Pass {
        id: verticalBlurPass3
        shaders: [glowVerticalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: tempBuffer3
            }
        ]
        output: glowBuffer3
    }

    Pass {
        id: horizontalBlurPass4
        shaders: [glowHorizontalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: glowBuffer3
            }
        ]
        output: tempBuffer4
    }

    Pass {
        id: verticalBlurPass4
        shaders: [glowVerticalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: tempBuffer4
            }
        ]
        output: glowBuffer4
    }

    Pass {
        id: horizontalBlurPass5
        shaders: [glowHorizontalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: glowBuffer4
            }
        ]
        output: tempBuffer5
    }

    Pass {
        id: verticalBlurPass5
        shaders: [glowVerticalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: tempBuffer5
            }
        ]
        output: glowBuffer5
    }

    Pass {
        id: horizontalBlurPass6
        shaders: [glowHorizontalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: glowBuffer5
            }
        ]
        output: tempBuffer6
    }

    Pass {
        id: verticalBlurPass6
        shaders: [glowVerticalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: tempBuffer6
            }
        ]
        output: glowBuffer6
    }
    Pass {
        id: horizontalBlurPass7
        shaders: [glowHorizontalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: glowBuffer6
            }
        ]
        output: tempBuffer7
    }

    Pass {
        id: verticalBlurPass7
        shaders: [glowVerticalBlur]
        commands: [
            SetUniformValue {
                target: "isFirstPass"
                value: false
            },
            BufferInput {
                buffer: tempBuffer7
            }
        ]
        output: glowBuffer7
    }

    Pass {
        id: lensFlareDownsamplePass
        shaders: [lensFlareDownsample]
        output: lensFlareDownsampleBuffer
    }

    Pass {
        id: lensFlareFeaturesPass
        shaders: [lensFlareFeatures]
        commands: [
            BufferInput {
                buffer: lensFlareDownsampleBuffer
                sampler: "lensFlareDownsampleBuffer"
            }
        ]
        output: lensFlareFeaturesBuffer
    }

    Pass {
        id: lensFlareBlurHorizontalPass
        shaders: [lensFlareHorizontalVert, lensFlareGaussianBlur]
        commands: [
            BufferInput {
                buffer: lensFlareFeaturesBuffer
                sampler: "lensFlareTexture"
            }
        ]
        output: lensFlareBlurTempBuffer
    }
    Pass {
        id: lensFlareBlurVerticalPass
        shaders: [lensFlareVerticalBlurVert, lensFlareGaussianBlur]
        commands: [
            BufferInput {
                buffer: lensFlareBlurTempBuffer
                sampler: "lensFlareTexture"
            }

        ]
        output: lensFlareBlurBuffer
    }

    Connections {
        target: sceneEffect
        function onIsGlowEnabledChanged() { tonemapPass.rebuildCommands() }
        function onLensFlareEnabledChanged() { tonemapPass.rebuildCommands() }
    }

    BufferInput {
        id: glowBufferInput1
        buffer: glowBuffer1
        sampler: "glowBuffer1"
    }
    BufferInput {
        id: glowBufferInput2
        buffer: glowBuffer2
        sampler: "glowBuffer2"
    }
    BufferInput {
        id: glowBufferInput3
        buffer: glowBuffer3
        sampler: "glowBuffer3"
    }
    BufferInput {
        id: glowBufferInput4
        buffer: glowBuffer4
        sampler: "glowBuffer4"
    }
    BufferInput {
        id: glowBufferInput5
        buffer: glowBuffer5
        sampler: "glowBuffer5"
    }
    BufferInput {
        id: glowBufferInput6
        buffer: glowBuffer6
        sampler: "glowBuffer6"
    }
    BufferInput {
        id: glowBufferInput7
        buffer: glowBuffer7
        sampler: "glowBuffer7"
    }
    BufferInput {
        id: lensFlareBufferInput
        buffer: lensFlareBlurBuffer
        sampler: "lensFlareTexture"
    }

    Pass {
        id: tonemapPass;
        shaders: [tonemapperFrag]

        function rebuildCommands() {
            let dynamicCommands = []
            if (sceneEffect.isGlowEnabled) {
                dynamicCommands.push(glowBufferInput1)
                dynamicCommands.push(glowBufferInput2)
                dynamicCommands.push(glowBufferInput3)
                dynamicCommands.push(glowBufferInput4)
                dynamicCommands.push(glowBufferInput5)
                dynamicCommands.push(glowBufferInput6)
                dynamicCommands.push(glowBufferInput7)
            }
            if (sceneEffect.lensFlareEnabled) {
                dynamicCommands.push(lensFlareBufferInput)
            }
            tonemapPass.commands = dynamicCommands; // qmllint disable read-only-property
        }
    }
}
