import QtQuick 2.6

Canvas {
    id: piechart

    property var slices

    property int innerOffset: 10
    property int legendOffset: 8
    property bool showLegend: true

    onSlicesChanged: piechart.requestPaint()

    onPaint: {
        var startR = -Math.PI/2

        var ctx = getContext('2d')
        ctx.reset()

        ctx.font = "" + constants.fontSizeSmall + "px '" + app.font.family + "', sans-serif"
        ctx.strokeStyle = Qt.rgba(1, 1, 1, 1)
        ctx.lineWidth = 2
        var pcx = width/2
        var pcy = height/2
        var radius = height/3

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
            var dx = Math.cos(phi) * (radius + innerOffset + legendOffset)
            var dy = Math.sin(phi) * (radius + innerOffset + legendOffset)
            var dx2 = Math.cos(phi) * (radius + innerOffset + 2 * legendOffset)
            var dy2 = Math.sin(phi) * (radius + innerOffset + 2 * legendOffset)
            ctx.lineWidth = 1
            ctx.beginPath()
            if (dx > 0) {
                var ddx = ctx.measureText(slice.text).width + 2 * constants.paddingMedium
                var xtext = pcx+dx2 + constants.paddingMedium
            } else {
                var ddx = -(ctx.measureText(slice.text).width + 2 * constants.paddingMedium)
                var xtext = pcx+dx2+ddx + constants.paddingMedium
            }
            ctx.moveTo(pcx+dx, pcy+dy)
            ctx.lineTo(pcx+dx2, pcy+dy2)
            ctx.lineTo(pcx+dx2+ddx, pcy+dy2)
            ctx.moveTo(pcx+dx2, pcy+dy2)

            ctx.fillText(slice.text, xtext, pcy+dy2 - constants.paddingXSmall)
            ctx.stroke()
        }

    }
}
