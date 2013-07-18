#*************************************************************************
# This is a Python library for the Adafruit Thermal Printer.
# Pick one up at --> http://www.adafruit.com/products/597
# These printers use TTL serial to communicate, 2 pins are required.
# IMPORTANT: On 3.3V systems (e.g. Raspberry Pi), use a 10K resistor on
# the RX pin (TX on the printer, green wire), or simply leave unconnected.
#
# Adafruit invests time and resources providing this open source code.
# Please support Adafruit and open-source hardware by purchasing products
# from Adafruit!
#
# Written by Limor Fried/Ladyada for Adafruit Industries.
# Python port by Phil Burgess for Adafruit Industries.
# MIT license, all text above must be included in any redistribution.
#*************************************************************************

# This is pretty much a 1:1 direct Python port of the Adafruit_Thermal
# library for Arduino.  All methods use the same naming conventions as the
# Arduino library, with only slight changes in parameter behavior where
# needed.  This should simplify porting existing Adafruit_Thermal-based
# printer projects to Raspberry Pi, BeagleBone, etc.  See printertest.py
# for an example.
#
# One significant change is the addition of the printImage() function,
# which ties this to the Python Imaging Library and opens the door to a
# lot of cool graphical stuff!
#
# TO DO:
# - Might use standard ConfigParser library to put thermal calibration
#   settings in a global configuration file (rather than in the library).
# - Make this use proper Python library installation procedure.
# - Trap errors properly.  Some stuff just falls through right now.
# - Add docstrings throughout!

# Python 2.X code using the library usu. needs to include the next line:
from __future__ import print_function
from serial import Serial
import time

class Adafruit_Thermal(Serial):

	resumeTime      =  0.0
	byteTime        =  0.0
	dotPrintTime    =  0.033
	dotFeedTime     =  0.0025
	prevByte        = '\n'
	column          =  0
	maxColumn       = 32
	charHeight      = 24
	lineSpacing     =  8
	barcodeHeight   = 50
	printMode       =  0
	defaultHeatTime = 175

	def __init__(self, *args, **kwargs):
		# If no parameters given, use default port & baud rate.
		# If only port is passed, use default baud rate.
		# If both passed, use those values.
		baudrate = 19200
		if len(args) == 0:
			args = [ "/dev/ttyAMA0", baudrate ]
		elif len(args) == 1:
			args = [ args[0], baudrate ]
		else:
			baudrate = args[1]

		# Calculate time to issue one byte to the printer.
		# 11 bits (not 8) to accommodate idle, start and stop bits.
		# Idle time might be unnecessary, but erring on side of
		# caution here.
		self.byteTime = 11.0 / float(baudrate)

		Serial.__init__(self, *args, **kwargs)

		# Remainder of this method was previously in begin()

		# The printer can't start receiving data immediately upon
		# power up -- it needs a moment to cold boot and initialize.
		# Allow at least 1/2 sec of uptime before printer can
		# receive data.
		self.timeoutSet(0.5)

		self.wake()
		self.reset()

		# Description of print settings from page 23 of the manual:
		# ESC 7 n1 n2 n3 Setting Control Parameter Command
		# Decimal: 27 55 n1 n2 n3
		# Set "max heating dots", "heating time", "heating interval"
		# n1 = 0-255 Max heat dots, Unit (8dots), Default: 7 (64 dots)
		# n2 = 3-255 Heating time, Unit (10us), Default: 80 (800us)
		# n3 = 0-255 Heating interval, Unit (10us), Default: 2 (20us)
		# The more max heating dots, the more peak current will cost
		# when printing, the faster printing speed. The max heating
		# dots is 8*(n1+1).  The more heating time, the more density,
		# but the slower printing speed.  If heating time is too short,
		# blank page may occur.  The more heating interval, the more
		# clear, but the slower printing speed.

		heatTime = kwargs.get('heattime', self.defaultHeatTime)
		self.writeBytes(
		  27,       # Esc
		  55,       # 7 (print settings)
		  20,       # Heat dots (20 = balance darkness w/no jams)
		  heatTime, # Lib default = 45
		  250)      # Heat interval (500 uS = slower but darker)

		# Description of print density from page 23 of the manual:
		# DC2 # n Set printing density
		# Decimal: 18 35 n
		# D4..D0 of n is used to set the printing density.
		# Density is 50% + 5% * n(D4-D0) printing density.
		# D7..D5 of n is used to set the printing break time.
		# Break time is n(D7-D5)*250us.
		# (Unsure of the default value for either -- not documented)

		printDensity   = 14 # 120% (can go higher, but text gets fuzzy)
		printBreakTime =  4 # 500 uS

		self.writeBytes(
		  18, # DC2
		  35, # Print density
		  (printBreakTime << 5) | printDensity)

		self.dotPrintTime = 0.03
		self.dotFeedTime  = 0.0021


	# Because there's no flow control between the printer and computer,
	# special care must be taken to avoid overrunning the printer's
	# buffer.  Serial output is throttled based on serial speed as well
	# as an estimate of the device's print and feed rates (relatively
	# slow, being bound to moving parts and physical reality).  After
	# an operation is issued to the printer (e.g. bitmap print), a
	# timeout is set before which any other printer operations will be
	# suspended.  This is generally more efficient than using a delay
	# in that it allows the calling code to continue with other duties
	# (e.g. receiving or decoding an image) while the printer
	# physically completes the task.

	# Sets estimated completion time for a just-issued task.
	def timeoutSet(self, x):
		self.resumeTime = time.time() + x

	# Waits (if necessary) for the prior task to complete.
	def timeoutWait(self):
		while (time.time() - self.resumeTime) < 0: pass


	# Printer performance may vary based on the power supply voltage,
	# thickness of paper, phase of the moon and other seemingly random
	# variables.  This method sets the times (in microseconds) for the
	# paper to advance one vertical 'dot' when printing and feeding.
	# For example, in the default initialized state, normal-sized text
	# is 24 dots tall and the line spacing is 32 dots, so the time for
	# one line to be issued is approximately 24 * print time + 8 * feed
	# time.  The default print and feed times are based on a random
	# test unit, but as stated above your reality may be influenced by
	# many factors.  This lets you tweak the timing to avoid excessive
	# delays and/or overrunning the printer buffer.
	def setTimes(self, p, f):
		# Units are in microseconds for
		# compatibility with Arduino library
		self.dotPrintTime = p / 1000000.0
		self.dotFeedTime  = f / 1000000.0


	# 'Raw' byte-writing method
	def writeBytes(self, *args):
		self.timeoutWait()
		self.timeoutSet(len(args) * self.byteTime)
		for arg in args:
			super(Adafruit_Thermal, self).write(chr(arg))


	# Override write() method to keep track of paper feed.
	def write(self, *data):
		for i in range(len(data)):
			c = data[i]
			if c != 0x13:
				self.timeoutWait()
				super(Adafruit_Thermal, self).write(c)
				d = self.byteTime
				if ((c == '\n') or
				    (self.column == self.maxColumn)):
					# Newline or wrap
					if self.prevByte == '\n':
						# Feed line (blank)
						d += ((self.charHeight +
						       self.lineSpacing) *
						      self.dotFeedTime)
					else:
						# Text line
						d += ((self.charHeight *
						       self.dotPrintTime) +
						      (self.lineSpacing *
						       self.dotFeedTime))
						self.column = 0
						# Treat wrap as newline
						# on next pass
						c = '\n'
				else:
					self.column += 1
				self.timeoutSet(d)
				self.prevByte = c


	# The bulk of this method was moved into __init__,
	# but this is left here for compatibility with older
	# code that might get ported directly from Arduino.
	def begin(self, heatTime=defaultHeatTime):
		self.writeBytes(
		  27,       # Esc
		  55,       # 7 (print settings)
		  20,       # Heat dots (20 = balance darkness w/no jams)
		  heatTime, # Lib default = 45
		  250)      # Heat interval (500 uS = slower but darker)


	def reset(self):
		self.prevByte      = '\n' # Treat as if prior line is blank
		self.column        =  0
		self.maxColumn     = 32
		self.charHeight    = 24
		self.lineSpacing   =  8
		self.barcodeHeight = 50
		self.writeBytes(27, 64)


	# Reset text formatting parameters.
	def setDefault(self):
		self.online()
		self.justify('L')
		self.inverseOff()
		self.doubleHeightOff()
		self.setLineHeight(32)
		self.boldOff()
		self.underlineOff()
		self.setBarcodeHeight(50)
		self.setSize('s')


	def test(self):
		self.writeBytes(18, 84)
		self.timeoutSet(
		  self.dotPrintTime * 24 * 26 +
		  self.dotFeedTime  * (8 * 26 + 32))


	UPC_A   =  0
	UPC_E   =  1
	EAN13   =  2
	EAN8    =  3
	CODE39  =  4
	I25     =  5
	CODEBAR =  6
	CODE93  =  7
	CODE128 =  8
	CODE11  =  9
	MSI     = 10

	def printBarcode(self, text, type):
		self.writeBytes(
		  29,  72, 2,    # Print label below barcode
		  29, 119, 3,    # Barcode width
		  29, 107, type) # Barcode type
		# Print string
		self.timeoutWait()
		self.timeoutSet((self.barcodeHeight + 40) * self.dotPrintTime)
		super(Adafruit_Thermal, self).write(text)
		self.prevByte = '\n'
		self.feed(2)

	def setBarcodeHeight(self, val=50):
		if val < 1:
			val = 1
		self.barcodeHeight = val
		self.writeBytes(29, 104, val)


	# === Character commands ===

	INVERSE_MASK       = (1 << 1)
	UPDOWN_MASK        = (1 << 2)
	BOLD_MASK          = (1 << 3)
	DOUBLE_HEIGHT_MASK = (1 << 4)
	DOUBLE_WIDTH_MASK  = (1 << 5)
	STRIKE_MASK        = (1 << 6)

	def setPrintMode(self, mask):
		self.printMode |= mask
		self.writePrintMode()
		if self.printMode & self.DOUBLE_HEIGHT_MASK:
			self.charHeight = 24
		else:
			self.charHeight = 48
		if self.printMode & self.DOUBLE_WIDTH_MASK:
			self.maxColumn  = 16
		else:
			self.maxColumn  = 32

	def unsetPrintMode(self, mask):
		self.printMode &= ~mask
		self.writePrintMode()

	def writePrintMode(self):
		self.writeBytes(27, 33, self.printMode)

	def normal(self):
		self.printMode = 0
		self.writePrintMode()

	def inverseOn(self):
		self.setPrintMode(self.INVERSE_MASK)

	def inverseOff(self):
		self.unsetPrintMode(self.INVERSE_MASK)

	def upsideDownOn(self):
		self.setPrintMode(self.UPDOWN_MASK)

	def upsideDownOff(self):
		self.unsetPrintMode(self.UPDOWN_MASK)

	def doubleHeightOn(self):
		self.setPrintMode(self.DOUBLE_HEIGHT_MASK)

	def doubleHeightOff(self):
		self.unsetPrintMode(self.DOUBLE_HEIGHT_MASK)

	def doubleWidthOn(self):
		self.setPrintMode(self.DOUBLE_WIDTH_MASK)

	def doubleWidthOff(self):
		self.unsetPrintMode(self.DOUBLE_WIDTH_MASK)

	def strikeOn(self):
		self.setPrintMode(self.STRIKE_MASK)

	def strikeOff(self):
		self.unsetPrintMode(self.STRIKE_MASK)

	def boldOn(self):
		self.setPrintMode(self.BOLD_MASK)

	def boldOff(self):
		self.unsetPrintMode(self.BOLD_MASK)


	def justify(self, value):
		c = value.upper()
		if   c == 'C':
			pos = 1
		elif c == 'R':
			pos = 2
		else:
			pos = 0
		self.writeBytes(0x1B, 0x61, pos)


	# Feeds by the specified number of lines
	def feed(self, x=1):
		# The datasheet claims sending bytes 27, 100, <x> will work,
		# but it feeds much more than that.  So it's done manually:
		while x > 0:
			self.write('\n')
			x -= 1


	# Feeds by the specified number of individual pixel rows
	def feedRows(self, rows):
		self.writeBytes(27, 74, rows)
		self.timeoutSet(rows * dotFeedTime)


	def flush(self):
		self.writeBytes(12)


	def setSize(self, value):
		c = value.upper()
		if c == 'L':   # Large: double width and height
			size            = 0x11
			self.charHeight = 48
			self.maxColumn  = 16
		elif c == 'M': # Medium: double height
			size            = 0x01
			self.charHeight = 48
			self.maxColumn  = 32
		else:          # Small: standard width and height
			size            = 0x00
			self.charHeight = 24
			self.maxColumn  = 32

		self.writeBytes(29, 33, size, 10)
		prevByte = '\n' # Setting the size adds a linefeed


	# Underlines of different weights can be produced:
	# 0 - no underline
	# 1 - normal underline
	# 2 - thick underline
	def underlineOn(self, weight=1):
		self.writeBytes(27, 45, weight)


	def underlineOff(self):
		self.underlineOn(0)


	def printBitmap(self, w, h, bitmap, LaaT=False):
		rowBytes = (w + 7) / 8  # Round up to next byte boundary
		if rowBytes >= 48:
			rowBytesClipped = 48  # 384 pixels max width
		else:
			rowBytesClipped = rowBytes

		# if LaaT (line-at-a-time) is True, print bitmaps
		# scanline-at-a-time (rather than in chunks).
		# This tends to make for much cleaner printing
		# (no feed gaps) on large images...but has the
		# opposite effect on small images that would fit
		# in a single 'chunk', so use carefully!
		if LaaT: maxChunkHeight = 1
		else:    maxChunkHeight = 255

		i = 0
		for rowStart in range(0, h, maxChunkHeight):
			chunkHeight = h - rowStart
			if chunkHeight > maxChunkHeight:
				chunkHeight = maxChunkHeight

			# Timeout wait happens here
			self.writeBytes(18, 42, chunkHeight, rowBytesClipped)

			for y in range(chunkHeight):
				for x in range(rowBytesClipped):
					super(Adafruit_Thermal, self).write(
					  chr(bitmap[i]))
					i += 1
				i += rowBytes - rowBytesClipped
			self.timeoutSet(chunkHeight * self.dotPrintTime)

		self.prevByte = '\n'

	# Print Image.  Requires Python Imaging Library.  This is
	# specific to the Python port and not present in the Arduino
	# library.  Image will be cropped to 384 pixels width if
	# necessary, and converted to 1-bit w/diffusion dithering.
	# For any other behavior (scale, B&W threshold, etc.), use
	# the Imaging Library to perform such operations before
	# passing the result to this function.
	def printImage(self, image, LaaT=False):
		import Image

		if image.mode != '1':
			image = image.convert('1')

		width  = image.size[0]
		height = image.size[1]
		if width > 384:
			width = 384
		rowBytes = (width + 7) / 8
		bitmap   = bytearray(rowBytes * height)
		pixels   = image.load()

		for y in range(height):
			n = y * rowBytes
			x = 0
			for b in range(rowBytes):
				sum = 0
				bit = 128
				while bit > 0:
					if x >= width: break
					if pixels[x, y] == 0:
						sum |= bit
					x    += 1
					bit >>= 1
				bitmap[n + b] = sum

		self.printBitmap(width, height, bitmap, LaaT)


	# Take the printer offline. Print commands sent after this
	# will be ignored until 'online' is called.
	def offline(self):
		self.writeBytes(27, 61, 0)


	# Take the printer online. Subsequent print commands will be obeyed.
	def online(self):
		self.writeBytes(27, 61, 1)


	# Put the printer into a low-energy state immediately.
	def sleep(self):
		self.sleepAfter(1)


	# Put the printer into a low-energy state after
	# the given number of seconds.
	def sleepAfter(self, seconds):
		self.writeBytes(27, 56, seconds)


	def wake(self):
		self.writeBytes(255)
		self.timeoutSet(0.5)


	# Empty method, included for compatibility
	# with existing code ported from Arduino.
	def listen(self):
		pass


	# Check the status of the paper using the printers self reporting
	# ability. Doesn't match the datasheet...
	# Returns True for paper, False for no paper.
	def hasPaper(self):
		self.writeBytes(27, 118, 0)
		# Bit 2 of response seems to be paper status
		stat = ord(self.read(1)) & 0b00000100
		# If set, we have paper; if clear, no paper
		return stat == 0


	def setLineHeight(self, val=32):
		if val < 24:
			val = 24
		self.lineSpacing = val - 24

		# The printer doesn't take into account the current text
		# height when setting line height, making this more akin
		# to inter-line spacing.  Default line spacing is 32
		# (char height of 24, line spacing of 8).
		self.writeBytes(27, 51, val)


	# Copied from Arduino lib for parity; is marked 'not working' there
	def tab(self):
		self.writeBytes(9)


	# Copied from Arduino lib for parity; is marked 'not working' there
	def setCharSpacing(self, spacing):
		self.writeBytes(27, 32, 0, 10)


	# Overloading print() in Python pre-3.0 is dirty pool,
	# but these are here to provide more direct compatibility
	# with existing code written for the Arduino library.
	def printChar(self, *args, **kwargs):
		for arg in args:
			self.write(str(arg))

	# For Arduino code compatibility again
	def println(self, *args, **kwargs):
		for arg in args:
			self.write(str(arg))
		self.write('\n')

