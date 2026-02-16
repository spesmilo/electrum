// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: heavyRain
    y: 2000
    ParticleEmitter3D {
        id: heavyRainEmitter
        emitRate: 50
        lifeSpan: 500
        shape: heavyRainShape
        particle: heavyRainParticle
        particleScale: 0.75
        particleScaleVariation: 0.25
        velocity: heavyRainDirection
        depthBias: -200

        VectorDirection3D {
            id: heavyRainDirection
            direction.y: -(heavyRain.y * 2)
        }

        SpriteParticle3D {
            id: heavyRainParticle
            color: "#73e6f4ff"
            maxAmount: 100
            particleScale: 100
            fadeInDuration: 0
            fadeOutDuration: 10
            fadeOutEffect: Particle3D.FadeOpacity
            sortMode: Particle3D.SortDistance
            sprite: heavyRainTexture
            spriteSequence: heavyRainSequence
            offsetY: heavyRainParticle.particleScale / 2
            billboard: true

            Texture {
                id: heavyRainTexture
                source: "rain.png"
            }

            SpriteSequence3D {
                id: heavyRainSequence
                duration: 15
                randomStart: true
                animationDirection: SpriteSequence3D.Normal
                frameCount: 3
                interpolate: true
            }
        }
    }

    ParticleShape3D {
        id: heavyRainShape
        extents.x: 500
        extents.y: 0.01
        extents.z: 500
        type: ParticleShape3D.Cube
        fill: true
    }

    TrailEmitter3D {
        id: heavyRainDropletEmitter
        emitRate: 0
        lifeSpan: 500
        particle: heavyRainDropletParticle
        particleScaleVariation: 0.2
        follow: heavyRainParticle
        emitBursts: heavyRainDropletBurst
        velocity: heavyRainDropletDirection
        depthBias: -8

        SpriteParticle3D {
            id: heavyRainDropletParticle
            color: "#5ea6e2ff"
            maxAmount: 300
            sprite: heavyRainDropletTexture
            particleScale: 3
            sortMode: Particle3D.SortDistance
            fadeInEffect: Particle3D.FadeScale
            fadeOutEffect: Particle3D.FadeScale
            fadeOutDuration: 200
            fadeInDuration: 100
            billboard: true

            Texture {
                id: heavyRainDropletTexture
                source: "sphere.png"
            }
        }

        DynamicBurst3D {
            id: heavyRainDropletBurst
            triggerMode: DynamicBurst3D.TriggerEnd
            amount: 1
            amountVariation: 1
        }

        VectorDirection3D {
            id: heavyRainDropletDirection
            direction.x: 0
            direction.y: 120
            direction.z: 0
            directionVariation.x: 150
            directionVariation.y: 100
            directionVariation.z: 150
        }
    }

    Gravity3D {
        id: heavyRainDropletGravity
        particles: heavyRainDropletParticle
        magnitude: 800
    }

    TrailEmitter3D {
        id: heavyRainPoolEmitter
        lifeSpan: 800
        emitRate: 0
        particle: heavyRainPoolParticle
        particleScale: 25
        particleRotation.x: -90
        follow: heavyRainParticle
        emitBursts: heavyRainPoolBurst
        depthBias: -10

        SpriteParticle3D {
            id: heavyRainPoolParticle
            color: "#11ecf9ff"
            maxAmount: 300
            sprite: heavyRainPoolTexture
            fadeOutEffect: Particle3D.FadeOpacity
            fadeInEffect: Particle3D.FadeScale
            fadeOutDuration: 800
            fadeInDuration: 150
            Texture {
                id: heavyRainPoolTexture
                source: "ripple.png"
            }
        }

        DynamicBurst3D {
            id: heavyRainPoolBurst
            triggerMode: DynamicBurst3D.TriggerEnd
            amount: 1
        }
    }

    TrailEmitter3D {
        id: heavyRainSplashEmitter
        emitRate: 0
        lifeSpan: 800
        particle: heavyRainSplashParticle
        particleScale: 15
        particleScaleVariation: 15
        particleRotation.x: 0
        follow: heavyRainParticle
        emitBursts: heavyRainSplashBurst
        depthBias: -10

        SpriteParticle3D {
            id: heavyRainSplashParticle
            color: "#94c0e7fb"
            billboard: true
            sprite: heavyRainSplashTexture
            spriteSequence: heavyRainSplashSequence
            sortMode: Particle3D.SortDistance
            fadeOutEffect: Particle3D.FadeOpacity
            fadeInEffect: Particle3D.FadeScale
            fadeOutDuration: 800
            fadeInDuration: 450
            offsetY: particleScale / 2
            Texture {
                id: heavyRainSplashTexture
                source: "splash7.png"
            }

            SpriteSequence3D {
                id: heavyRainSplashSequence
                duration: 800
                frameCount: 6
            }
            maxAmount: 1500
        }

        DynamicBurst3D {
            id: heavyRainSplashBurst
            triggerMode: DynamicBurst3D.TriggerEnd
            amount: 1
        }
    }
}
