import QtQuick 2.6

Canvas {
    id: piechart

    property var slices

    property int innerOffset: 10
    property bool showLegend: true

    onPaint: {
        var startR = -Math.PI/2

        var ctx = getContext('2d')
        ctx.reset()

        ctx.strokeStyle = Qt.rgba(1, 1, 1, 1)
        ctx.lineWidth = 2
        var pcx = width/2
        var pcy = height/2
        var radius = height/4

        var endR = startR
        for (const i in slices) {
            var slice = slices[i]
            if (slice.v == 0)
                continue
            startR = endR
            endR = startR + 2*Math.PI*(slice.v)

            // displace origin
            var phi = startR + (endR - startR)/2
            var dx = Math.cos(phi) * innerOffset
            var dy = Math.sin(phi) * innerOffset

            ctx.lineWidth = 2
            ctx.fillStyle = slice.color
            ctx.beginPath()
            ctx.moveTo(pcx+dx, pcy+dy)
            ctx.arc(pcx+dx, pcy+dy, radius, startR, endR, false)
            ctx.lineTo(pcx+dx, pcy+dy)
            ctx.fill()
            // ctx.stroke()

            if (!showLegend)
                continue

            // displace legend
            var dx = Math.cos(phi) * (radius + innerOffset + constants.paddingMedium)
            var dy = Math.sin(phi) * (radius + innerOffset + constants.paddingMedium)
            ctx.lineWidth = 1
            ctx.beginPath()
            if (dx > 0) {
                var ddx = ctx.measureText(slice.text).width + 2 * constants.paddingMedium
                var xtext = pcx+dx*1.2 + constants.paddingMedium
            } else {
                var ddx = -(ctx.measureText(slice.text).width + 2 * constants.paddingMedium)
                var xtext = pcx+dx*1.2+ddx + constants.paddingMedium
            }
            ctx.moveTo(pcx+dx, pcy+dy)
            ctx.lineTo(pcx+dx*1.2, pcy+dy*1.2)
            ctx.lineTo(pcx+dx*1.2+ddx, pcy+dy*1.2)
            ctx.moveTo(pcx+dx*1.2, pcy+dy*1.2)

            ctx.text(slice.text, xtext, pcy+dy*1.2 - constants.paddingXSmall)
            ctx.stroke()
        }

    }
}
