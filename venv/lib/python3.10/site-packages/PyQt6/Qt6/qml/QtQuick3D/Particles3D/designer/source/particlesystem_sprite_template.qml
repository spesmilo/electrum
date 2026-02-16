// Copyright (C) 2021 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

import QtQuick
import QtQuick3D
import QtQuick3D.Particles3D

ParticleSystem3D {
    id: spriteSystem
    ParticleEmitter3D {
        id: spriteEmitter
        velocity: spriteDirection
        particle: spriteParticle
        lifeSpan: 2000
        emitRate: 200
        SpriteParticle3D {
            id: spriteParticle
            maxAmount: 1000
        }

        VectorDirection3D {
            id: spriteDirection
            directionVariation.z: 10
            directionVariation.y: 10
            directionVariation.x: 10
        }
    }
}
