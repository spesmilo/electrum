// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: lightRainTireSpray
    ParticleEmitter3D {
        id: lightRainTireMistEmitter
        emitRate: 15
        lifeSpan: 700
        enabled: true
        particle: lightRainTireMistParticle
        particleScale: 5
        particleEndScale: 20
        particleScaleVariation: 5
        shape: lightRainTireSprayMistShape
        lifeSpanVariation: 300
        velocity: lightRainTireMistDirection
        depthBias: -20

        SpriteParticle3D {
            id: lightRainTireMistParticle
            color: "#c5e3eaf2"
            particleScale: 12
            fadeInDuration: 200
            fadeOutDuration: 350
            fadeInEffect: Particle3D.FadeOpacity
            sortMode: Particle3D.SortNewest
            blendMode: SpriteParticle3D.SourceOver
            spriteSequence: lightRainTireSpraySequence
            sprite: lightRainTireSprayTexture
            billboard: true
            maxAmount: 1000

            Wander3D {
                id: lightRainTireMistWander
                enabled: true
                fadeOutDuration: 500
                fadeInDuration: 300
                uniquePaceVariation: 1
                uniqueAmountVariation: 1
                uniquePace.y: 0.03
                uniqueAmount.y: 20
                particles: lightRainTireMistParticle
                system: lightRainTireSpray
            }

            VectorDirection3D {
                id: lightRainTireMistDirection
                directionVariation.x: 100
                directionVariation.y: 10
                directionVariation.z: 250
                direction.y: 10
            }
        }

        ParticleShape3D {
            id: lightRainTireSprayMistShape
            fill: true
            extents.x: 1
            extents.y: 15
            extents.z: 20
        }
    }

    ParticleEmitter3D {
        id: lightRainStream
        emitRate: 10
        particleEndScale: 7
        particle: lightRainStreamParticle
        particleScale: 5
        particleScaleVariation: 1
        lifeSpan: 450
        lifeSpanVariation: 50
        velocity: lightRainStreamDirection
        depthBias: -20

        SpriteParticle3D {
            id: lightRainStreamParticle
            color: "#f6f9ff"
            fadeOutEffect: Particle3D.FadeOpacity
            fadeOutDuration: 300
            fadeInEffect: Particle3D.FadeOpacity
            sortMode: Particle3D.SortNewest
            blendMode: SpriteParticle3D.Screen
            spriteSequence: lightRainTireSpraySequence
            maxAmount: 1000
            billboard: false
            particleScale: 12
            fadeInDuration: 300
            sprite: lightRainTireSprayTexture

            SpriteSequence3D {
                id: lightRainTireSpraySequence
                duration: 2000
                frameCount: 15
            }
            VectorDirection3D {
                id: lightRainStreamDirection
                direction.y: 60
                directionVariation.y: 10
                directionVariation.z: 20
            }
        }
    }

    Texture {
        id: lightRainTireSprayTexture
        source: "smoke2.png"
    }

    Gravity3D {
        id: lightRainTireSprayGravity
        magnitude: 1500
        system: lightRainTireSpray
        direction.x: 1
        direction.y: 0
        direction.z: 0
        particles: [lightRainTireMistParticle, lightRainStreamParticle]
    }
}
