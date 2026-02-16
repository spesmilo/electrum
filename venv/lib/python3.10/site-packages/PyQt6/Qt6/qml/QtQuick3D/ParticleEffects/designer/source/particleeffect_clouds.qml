// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: cloudSystem
    ParticleEmitter3D {
        id: baseCloudEmitter
        emitRate: 0
        lifeSpan: 200000
        particle: cloudParticle
        particleScale: 35
        particleScaleVariation: 10
        emitBursts: cloudBaseBurst
        velocity: cloudDirection
        shape: cloudShape
        depthBias: -20
        SpriteParticle3D {
            id: cloudParticle
            color: "#bcffffff"
            particleScale: 12
            fadeInEffect: Particle3D.FadeScale
            fadeInDuration: 0
            fadeOutDuration: 0
            blendMode: SpriteParticle3D.SourceOver
            sprite: cloudTexture
            spriteSequence: cloudSequence
            billboard: true
            maxAmount: 50
            sortMode: Particle3D.SortNewest
            Texture {
                id: cloudTexture
                source: "smoke_sprite2.png"
            }
            SpriteSequence3D {
                id: cloudSequence
                animationDirection: SpriteSequence3D.Alternate
                durationVariation: 3000
                interpolate: true
                randomStart: true
                frameCount: 15
                duration: 50000
            }
        }

        ParticleShape3D {
            id: cloudShape
            type: ParticleShape3D.Sphere
            fill: false
            extents.z: 250
            extents.y: 100
            extents.x: 250
        }

        DynamicBurst3D {
            id: cloudBaseBurst
            amount: 10
        }
    }

    ParticleEmitter3D {
        id: smallCloudEmitter
        lifeSpan: 2000000
        emitRate: 0
        particle: cloudSmallParticle
        particleScale: 18
        particleScaleVariation: 7
        velocity: cloudDirection
        shape: cloudOuterShape
        emitBursts: cloudSmallBurst
        depthBias: -25
        SpriteParticle3D {
            id: cloudSmallParticle
            color: "#65ffffff"
            maxAmount: 75
            particleScale: 12
            fadeOutDuration: 0
            fadeInDuration: 0
            fadeInEffect: Particle3D.FadeScale
            blendMode: SpriteParticle3D.SourceOver
            sortMode: Particle3D.SortNewest
            spriteSequence: cloudSequence
            sprite: cloudTexture
            billboard: true
        }

        ParticleShape3D {
            id: cloudOuterShape
            extents.x: 350
            extents.y: 150
            extents.z: 350
            fill: true
            type: ParticleShape3D.Sphere
        }

        DynamicBurst3D {
            id: cloudSmallBurst
            amount: 15
        }
    }
    VectorDirection3D {
        id: cloudDirection
        direction.y: 0
        direction.z: -20
    }
    Wander3D {
        id: cloudWander
        uniqueAmountVariation: 0.3
        uniqueAmount.x: 15
        uniqueAmount.y: 15
        uniqueAmount.z: 15
        uniquePace.x: 0.01
        uniquePace.y: 0.01
        uniquePace.z: 0.01
        particles: [cloudParticle, cloudSmallParticle, smallCloudEmitter]
        system: cloudSystem
    }
}
