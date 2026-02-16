// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: heavyRainTireSpray
    ParticleEmitter3D {
        id: heavyRainTireMistEmitter
        emitRate: 45
        lifeSpan: 800
        lifeSpanVariation: 300
        particle: heavyRainTireMistParticle
        particleScale: 5
        particleEndScale: 25
        particleScaleVariation: 5
        shape: heavyRainTireMistShape
        velocity: heavyRainTireMistDirection
        depthBias: -20

        SpriteParticle3D {
            id: heavyRainTireMistParticle
            color: "#c5e3eaf2"
            maxAmount: 100
            particleScale: 12
            fadeInDuration: 200
            fadeOutDuration: 350
            sprite: heavyRainTireSprayTexture
            spriteSequence: heavyRainTireSpraySequence
            sortMode: Particle3D.SortNewest
            fadeInEffect: Particle3D.FadeOpacity
            blendMode: SpriteParticle3D.SourceOver
            billboard: true

            Wander3D {
                id: heavyRainTireMistWander
                enabled: true
                fadeOutDuration: 500
                fadeInDuration: 300
                uniquePaceVariation: 1
                uniqueAmountVariation: 1
                uniquePace.y: 0.03
                uniqueAmount.y: 20
                particles: heavyRainTireMistParticle
                system: heavyRainTireSpray
            }

            VectorDirection3D {
                id: heavyRainTireMistDirection
                directionVariation.x: 100
                directionVariation.y: 10
                direction.y: 10
                directionVariation.z: 250
            }
        }

        ParticleShape3D {
            id: heavyRainTireMistShape
            fill: true
            extents.x: 1
            extents.z: 20
            extents.y: 15
        }
    }

    ParticleEmitter3D {
        id: heavyRainTireStreamLeft
        emitRate: 20
        particle: heavyRainTireStreamLeftParticle
        particleScale: 15
        particleEndScale: 75
        particleRotation.x: 90
        particleScaleVariation: 5
        velocity: heavyRainTireStreamLeftDirection
        lifeSpanVariation: 100
        lifeSpan: 750
        depthBias: -15

        SpriteParticle3D {
            id: heavyRainTireStreamLeftParticle
            color: "#cdacb1b8"
            maxAmount: 1000
            fadeInDuration: 350
            fadeOutDuration: 200
            billboard: false
            sprite: heavyRainTireSprayTexture
            spriteSequence: heavyRainTireSpraySequence
            blendMode: SpriteParticle3D.Screen
            fadeInEffect: Particle3D.FadeScale
            sortMode: Particle3D.SortNewest
        }

        VectorDirection3D {
            id: heavyRainTireStreamLeftDirection
            direction.x: -200
            direction.y: 0
            direction.z: 175
            directionVariation.z: 25
        }
    }

    ParticleEmitter3D {
        id: heavyRainTireStreamRight
        depthBias: -15
        enabled: true
        particleRotation.x: 90
        particleScaleVariation: 5
        velocity: heavyRainTireStreamRightDirection
        lifeSpanVariation: 100
        particleEndScale: 75
        lifeSpan: 750
        emitRate: 20
        particleScale: 15
        particle: heavyRainTireStreamRightParticle

        SpriteParticle3D {
            id: heavyRainTireStreamRightParticle
            color: "#cdacb1b8"
            fadeOutDuration: 200
            fadeInEffect: Particle3D.FadeScale
            sortMode: Particle3D.SortNewest
            blendMode: SpriteParticle3D.Screen
            spriteSequence: heavyRainTireSpraySequence
            maxAmount: 1000
            billboard: false
            fadeInDuration: 350
            sprite: heavyRainTireSprayTexture
        }

        VectorDirection3D {
            id: heavyRainTireStreamRightDirection
            direction.y: 0
            directionVariation.z: 25
            direction.x: -200
            direction.z: -175
        }
    }

    ParticleEmitter3D {
        id: heavyRainTireStreamMiddle
        x: 50.704
        emitRate: 20
        particleEndScale: 7
        particle: heavyRainTireStreamMiddleParticle
        particleScale: 5
        particleScaleVariation: 1
        lifeSpan: 450
        lifeSpanVariation: 50
        velocity: heavyRainTireStreamMiddleDirection
        depthBias: -20

        SpriteParticle3D {
            id: heavyRainTireStreamMiddleParticle
            color: "#f6f9ff"
            fadeOutEffect: Particle3D.FadeOpacity
            fadeOutDuration: 300
            fadeInEffect: Particle3D.FadeOpacity
            sortMode: Particle3D.SortNewest
            blendMode: SpriteParticle3D.Screen
            spriteSequence: heavyRainTireSpraySequence
            maxAmount: 1000
            billboard: false
            particleScale: 12
            fadeInDuration: 300
            sprite: heavyRainTireSprayTexture

            SpriteSequence3D {
                id: heavyRainTireSpraySequence
                duration: 2000
                frameCount: 15
            }

            VectorDirection3D {
                id: heavyRainTireStreamMiddleDirection
                direction.y: 60
                directionVariation.z: 20
                directionVariation.y: 10
            }
        }
    }
    Texture {
        id: heavyRainTireSprayTexture
        source: "smoke2.png"
    }

    Gravity3D {
        id: heavyRainTireSprayGravity
        magnitude: 1500
        system: heavyRainTireSpray
        direction.x: 1
        direction.y: 0
        direction.z: 0
        particles: [heavyRainTireMistParticle, heavyRainTireStreamLeftParticle, heavyRainTireStreamRightParticle, heavyRainTireStreamMiddleParticle]
    }
}
