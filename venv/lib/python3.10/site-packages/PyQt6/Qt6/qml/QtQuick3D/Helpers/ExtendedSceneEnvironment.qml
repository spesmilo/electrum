// Copyright (C) 2022 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D.Helpers.impl

SceneEffectEnvironment {
    id: sceneEnvironment

    // Depth of Field Effect
    property alias depthOfFieldEnabled: dofBlurEffect.enabled
    property alias depthOfFieldFocusDistance: dofBlurEffect.focusDistance
    property alias depthOfFieldFocusRange: dofBlurEffect.focusRange
    property alias depthOfFieldBlurAmount: dofBlurEffect.blurAmount

    // Tonemapper
    property alias exposure: sceneEffect.exposure
    property alias whitePoint: sceneEffect.white
    property alias ditheringEnabled: sceneEffect.ditheringEnabled
    property alias sharpnessAmount: sceneEffect.sharpnessAmount

    // FXAA
    property alias fxaaEnabled: sceneEffect.applyFXAA

    // Adjustments
    property alias colorAdjustmentsEnabled: sceneEffect.colorAdjustmentsEnabled
    property alias adjustmentBrightness: sceneEffect.adjustmentBrightness
    property alias adjustmentContrast: sceneEffect.adjustmentContrast
    property alias adjustmentSaturation: sceneEffect.adjustmentSaturation

    // Color Grading Effect
    property alias lutEnabled: sceneEffect.enableLut
    property alias lutSize: sceneEffect.lutSize
    property alias lutFilterAlpha: sceneEffect.lutFilterAlpha
    property alias lutTexture: sceneEffect.lutTextureAlias

    // Glow Effect
    enum GlowBlendMode {
        Additive,
        Screen,
        SoftLight, // Default
        Replace
    }

    enum GlowLevel {
        One = 0x1,
        Two = 0x2,
        Three = 0x4,
        Four = 0x8,
        Five = 0x10,
        Six = 0x20,
        Seven = 0x40
    }

    property alias glowEnabled: sceneEffect.isGlowEnabled
    property alias glowQualityHigh: sceneEffect.glowQualityHigh
    property alias glowUseBicubicUpscale: sceneEffect.glowUseBicubicUpscale
    property alias glowStrength: sceneEffect.glowStrength
    property alias glowIntensity: sceneEffect.glowIntensity
    property alias glowBloom: sceneEffect.glowBloom
    property alias glowBlendMode: sceneEffect.glowBlendMode
    property alias glowHDRMaximumValue: sceneEffect.glowHDRMaximumValue
    property alias glowHDRScale: sceneEffect.glowHDRScale
    property alias glowHDRMinimumValue: sceneEffect.glowHDRMinimumValue
    property alias glowLevel: sceneEffect.glowLevel

    // Vignette
    property alias vignetteEnabled: sceneEffect.vignetteEnabled
    property alias vignetteStrength: sceneEffect.vignetteStrength
    property alias vignetteColor: sceneEffect.vignetteColor
    property alias vignetteRadius: sceneEffect.vignetteRadius

    // Lens Flare
    property alias lensFlareEnabled: sceneEffect.lensFlareEnabled
    property alias lensFlareBloomScale: sceneEffect.lensFlareBloomScale
    property alias lensFlareBloomBias: sceneEffect.lensFlareBloomBias
    property alias lensFlareGhostDispersal: sceneEffect.lensFlareGhostDispersal
    property alias lensFlareGhostCount: sceneEffect.lensFlareGhostCount
    property alias lensFlareHaloWidth: sceneEffect.lensFlareHaloWidth
    property alias lensFlareStretchToAspect: sceneEffect.lensFlareStretchToAspect
    property alias lensFlareDistortion: sceneEffect.lensFlareDistortion
    property alias lensFlareBlurAmount: sceneEffect.lensFlareBlurAmount
    property alias lensFlareApplyDirtTexture: sceneEffect.lensFlareApplyDirtTexture
    property alias lensFlareApplyStarburstTexture: sceneEffect.lensFlareApplyStarburstTexture
    property alias lensFlareCameraDirection: sceneEffect.lensFlareCameraDirection
    property alias lensFlareLensColorTexture: sceneEffect.lensColorTextureAlias
    property alias lensFlareLensDirtTexture: sceneEffect.lensDirtTextureAlias
    property alias lensFlareLensStarburstTexture: sceneEffect.starburstTextureAlias

    DepthOfFieldBlur {
        id: dofBlurEffect
        environment: sceneEnvironment
    }

    SceneEffect {
        id: sceneEffect
        environment: sceneEnvironment
        tonemapMode: sceneEnvironment.tonemapMode
    }
}
