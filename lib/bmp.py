# -*- coding: utf-8 -*-
"""
bmp.py - module for constructing simple BMP graphics files

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the
 "Software"), to deal in the Software without restriction, including
 without limitation the rights to use, copy, modify, merge, publish,
 distribute, sublicense, and/or sell copies of the Software, and to
 permit persons to whom the Software is furnished to do so, subject to
 the following conditions:

 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
__version__ = "0.3"
__about =  "bmp module, version %s, written by Paul McGuire, October, 2003, updated by Margus Laak, September, 2009" % __version__

from math import ceil, hypot


def shortToString(i):
  hi = (i & 0xff00) >> 8
  lo = i & 0x00ff
  return chr(lo) + chr(hi)

def longToString(i):
  hi = (long(i) & 0x7fff0000) >> 16
  lo = long(i) & 0x0000ffff
  return shortToString(lo) + shortToString(hi)

def long24ToString(i):
  return chr(i & 0xff) + chr(i >> 8 & 0xff) + chr(i >> 16 & 0xff)

def stringToLong(input_string, offset):
  return ord(input_string[offset+3]) << 24 | ord(input_string[offset+2]) << 16 | ord(input_string[offset+1]) << 8 | ord(input_string[offset])

def stringToLong24(input_string, offset):
  return ord(input_string[offset+2]) << 16 | ord(input_string[offset+1]) << 8 | ord(input_string[offset])

class Color(object):
  """class for specifying colors while drawing BitMap elements"""
  __slots__ = [ 'red', 'grn', 'blu' ]
  __shade = 32

  def __init__( self, r=0, g=0, b=0 ):
    self.red = r
    self.grn = g
    self.blu = b

  def __setattr__(self, name, value):
    if hasattr(self, name):
      raise AttributeError, "Color is immutable"
    else:
      object.__setattr__(self, name, value)

  def __str__( self ):
    return "R:%d G:%d B:%d" % (self.red, self.grn, self.blu )

  def __hash__( self ):
    return ( ( long(self.blu) ) +
              ( long(self.grn) <<  8 ) +
              ( long(self.red) << 16 ) )

  def __eq__( self, other ):
    return (self is other) or (self.toLong == other.toLong)

  def lighten( self ):
    return Color(
      min( self.red + Color.__shade, 255),
      min( self.grn + Color.__shade, 255),
      min( self.blu + Color.__shade, 255)
      )

  def darken( self ):
    return Color(
      max( self.red - Color.__shade, 0),
      max( self.grn - Color.__shade, 0),
      max( self.blu - Color.__shade, 0)
      )

  def toLong( self ):
    return self.__hash__()

  def fromLong( l ):
    b = l & 0xff
    l = l >> 8
    g = l & 0xff
    l = l >> 8
    r = l & 0xff
    return Color( r, g, b )
  fromLong = staticmethod(fromLong)

# define class constants for common colors
Color.BLACK    = Color(   0,   0,   0 )
Color.RED      = Color( 255,   0,   0 )
Color.GREEN    = Color(   0, 255,   0 )
Color.BLUE     = Color(   0,   0, 255 )
Color.CYAN     = Color(   0, 255, 255 )
Color.MAGENTA  = Color( 255,   0, 255 )
Color.YELLOW   = Color( 255, 255,   0 )
Color.WHITE    = Color( 255, 255, 255 )
Color.DKRED    = Color( 128,   0,   0 )
Color.DKGREEN  = Color(   0, 128,   0 )
Color.DKBLUE   = Color(   0,   0, 128 )
Color.TEAL     = Color(   0, 128, 128 )
Color.PURPLE   = Color( 128,   0, 128 )
Color.BROWN    = Color( 128, 128,   0 )
Color.GRAY     = Color( 128, 128, 128 )


class BitMap(object):
  """class for drawing and saving simple Windows bitmap files"""

  LINE_SOLID  = 0
  LINE_DASHED = 1
  LINE_DOTTED = 2
  LINE_DOT_DASH=3
  _DASH_LEN = 12.0
  _DOT_LEN = 6.0
  _DOT_DASH_LEN = _DOT_LEN + _DASH_LEN

  def __init__( self, width, height,
                 bkgd = Color.WHITE, frgd = Color.BLACK ):
    self.wd = int( ceil(width) )
    self.ht = int( ceil(height) )
    self.bgcolor = 0
    self.fgcolor = 1
    self.palette = []
    self.palette.append( bkgd.toLong() )
    self.palette.append( frgd.toLong() )
    self.currentPen = self.fgcolor

    tmparray = [ self.bgcolor ] * self.wd
    self.bitarray = [ tmparray[:] for i in range( self.ht ) ]
    self.currentPen = 1


  def plotPoint( self, x, y ):
    if ( 0 <= x < self.wd and 0 <= y < self.ht ):
      x = int(x)
      y = int(y)
      self.bitarray[y][x] = self.currentPen


  def _saveBitMapNoCompression( self ):
    line_padding = (4 - (self.wd % 4)) % 4

    # write bitmap header
    _bitmap = "BM"
    _bitmap += longToString( 54 + self.ht*(self.wd*3 + line_padding) )   # DWORD size in bytes of the file
    _bitmap += longToString( 0 )    # DWORD 0
    _bitmap += longToString( 54  )
    _bitmap += longToString( 40 )    # DWORD header size = 40
    _bitmap += longToString( self.wd )    # DWORD image width
    _bitmap += longToString( self.ht )    # DWORD image height
    _bitmap += shortToString( 1 )    # WORD planes = 1
    _bitmap += shortToString( 24 )    # WORD bits per pixel = 8
    _bitmap += longToString( 0 )    # DWORD compression = 0
    _bitmap += longToString( self.ht * (self.wd * 3 + line_padding) )    # DWORD sizeimage = size in bytes of the bitmap = width * height
    _bitmap += longToString( 0 )    # DWORD horiz pixels per meter (?)
    _bitmap += longToString( 0 )    # DWORD ver pixels per meter (?)
    _bitmap += longToString( 0 )    # DWORD number of colors used = 256
    _bitmap += longToString( 0 )    # DWORD number of "import colors = len( self.palette )

    # write pixels
    self.bitarray.reverse()
    rows = []
    for row in self.bitarray:
      for pixel in row:
        c = self.palette[pixel]
        rows.append(long24ToString(c))
      rows.append(chr(0) * line_padding)
    _bitmap += ''.join(rows)

    return _bitmap



  def saveFile( self, filename):
    _b = self._saveBitMapNoCompression( )

    f = file(filename, 'wb')
    f.write(_b)
    f.close()


def save_qrcode(qr, filename):
    matrix = qr.get_matrix()
    k = len(matrix)
    bitmap = BitMap( (k+2)*8, (k+2)*8 )
    bitmap.bitarray = []
    for r in range(k+2):
        tmparray = [ 0 ] * (k+2)*8

        if 0 < r < k+1:
            for c in range(k):
                if matrix[r-1][c]:
                    tmparray[ (1+c)*8:(2+c)*8] = [1]*8

        for i in range(8):
            bitmap.bitarray.append( tmparray[:] )

    bitmap.saveFile( filename )



if __name__ == "__main__":

  bmp = BitMap( 10, 10 )
  bmp.plotPoint( 5, 5 )
  bmp.plotPoint( 0, 0 )
  bmp.saveFile( "test.bmp" )
