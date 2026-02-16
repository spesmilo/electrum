// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    ParticleEmitter3D {
        id: smokeEmitter
        emitRate: 20
        lifeSpan: 1500
        lifeSpanVariation: 750
        particle: smokeParticle
        particleScale: 1
        particleScaleVariation: 4
        particleEndScale: 25
        velocity: smokeDirection

        VectorDirection3D {
            id: smokeDirection
            directionVariation.x: 10
            directionVariation.y: 10
            directionVariation.z: 10
            direction.y: 75
        }

        SpriteParticle3D {
            id: smokeParticle
            color: "#ffffff"
            maxAmount: 400
            particleScale: 5
            fadeInDuration: 3500
            fadeOutDuration: 1250
            sortMode: Particle3D.SortNewest
            blendMode: SpriteParticle3D.SourceOver
            billboard: true
            sprite: smokeTexture
            spriteSequence: spriteSequence

            Texture {
                id: smokeTexture
                source: "smoke_sprite.png"
            }

            SpriteSequence3D {
                id: spriteSequence
                duration: 6000
                frameCount: 15
            }
        }
    }

    ParticleEmitter3D {
        id: sparkEmitter
        emitRate: 10
        lifeSpan: 800
        lifeSpanVariation: 600
        particle: sparkParticle
        particleScaleVariation: 1
        velocity: sparkDirection
        depthBias: -100

        VectorDirection3D {
            id: sparkDirection
            directionVariation.x: 25
            directionVariation.y: 10
            directionVariation.z: 25
            direction.y: 60
        }

        SpriteParticle3D {
            id: sparkParticle
            color: "#ffffff"
            maxAmount: 100
            particleScale: 1
            fadeOutEffect: Particle3D.FadeScale
            sortMode: Particle3D.SortNewest
            blendMode: SpriteParticle3D.Screen
            billboard: true
            sprite: sphereTexture
            colorTable: colorTable

            Texture {
                id: sphereTexture
                source: "sphere.png"
            }

            Texture {
                id: colorTable
                source: "colorTable.png"
            }
        }
    }

    ParticleEmitter3D {
        id: fireEmitter
        emitRate: 90
        lifeSpan: 750
        lifeSpanVariation: 100
        particle: fireParticle
        particleScale: 3
        particleScaleVariation: 2
        velocity: fireDirection
        depthBias: -100

        VectorDirection3D {
            id: fireDirection
            directionVariation.x: 10
            directionVariation.z: 10
            direction.y: 75
        }

        SpriteParticle3D {
            id: fireParticle
            maxAmount: 500
            color: "#ffffff"
            colorTable: colorTable2
            sprite: sphereTexture
            sortMode: Particle3D.SortNewest
            fadeInEffect: Particle3D.FadeScale
            fadeOutEffect: Particle3D.FadeOpacity
            blendMode: SpriteParticle3D.Screen
            billboard: true

            Texture {
                id: colorTable2
                source: "color_table2.png"
            }

        }
    }

    Gravity3D {
        id: sparkGravity
        magnitude: 100
        particles: sparkParticle
        enabled: true
    }
}
