#!/usr/bin/python
import Image
import ImageDraw
import ImageFont
import qrcode
import sys
from Adafruit_Thermal import *

def print_seed(seed):

	printer = Adafruit_Thermal("/dev/ttyAMA0", 19200, timeout=5)


	printer.println(seed)
	
	printer.feed(3)


	printer.sleep()      # Tell printer to sleep
	printer.wake()       # Call wake() before printing again, even if reset
	printer.setDefault() # Restore printer to defaults



def print_keypair(pubkey, privkey):

#open the printer itself
	printer = Adafruit_Thermal("/dev/ttyAMA0", 19200, timeout=5)


#load a blank image of the paper wallet with no QR codes or keys on it which we will draw on
	finalImg = Image.open("/home/pi/Printer/btc-wallet-blank.bmp")




#---begin the public key qr code generation and drawing section---

#we begin the QR code creation process
#feel free to change the error correct level as you see fit
	qr = qrcode.QRCode(
	    version=None,
	    error_correction=qrcode.constants.ERROR_CORRECT_M,
	    box_size=10,
	    border=0,
	)

	qr.add_data(pubkey)
	qr.make(fit=True)

	pubkeyImg = qr.make_image()

#resize the qr code to match our design
	pubkeyImg = pubkeyImg.resize((175,175), Image.NEAREST)


	font = ImageFont.truetype("/usr/share/fonts/ttf/ubuntu-font-family-0.80/UbuntuMono-R.ttf", 20)
	draw = ImageDraw.Draw(finalImg)


	startPos=(110,38)
	charDist=15
	lineHeight=23
	lastCharPos=0

	keyLength = len(pubkey)

#draw 2 lines of 17 characters each.  keyLength always == 34 so keylength/17 == 2
	for x in range(0,keyLength/17):
		lastCharPos=0
		#print a line
		for y in range(0, 17):
			theChar = pubkey[(x*17)+y]
			charSize = draw.textsize(theChar, font=font)
			
			#if y is 0 then this is the first run of this loop, and we should use startPos[0] for the x coordinate instead of the lastCharPos
			if y == 0:
				draw.text((startPos[0],startPos[1]+(lineHeight*x)),theChar, font=font, fill=(0,0,0))
				lastCharPos = startPos[0]+charSize[0]+(charDist-charSize[0])
			else:
				draw.text((lastCharPos,startPos[1]+(lineHeight*x)),theChar, font=font, fill=(0,0,0))
				lastCharPos = lastCharPos + charSize[0] + (charDist-charSize[0])



#draw the QR code on the final image
	finalImg.paste(pubkeyImg, (150, 106))

#---end the public key qr code generation and drawing section---





#---begin the private key qr code generation and drawing section---

#we begin the QR code creation process
#feel free to change the error correct level as you see fit
	qr = qrcode.QRCode(
	    version=None,
	    error_correction=qrcode.constants.ERROR_CORRECT_M,
	    box_size=10,
	    border=0,
	)
	qr.add_data(privkey)
	qr.make(fit=True)

	privkeyImg = qr.make_image()

#resize the qr code to match our design
	privkeyImg = privkeyImg.resize((220,220), Image.NEAREST)


	startPos=(110,807)
	charDist=15
	lineHeight=23
	lastCharPos=0

	keyLength = len(privkey)

#draw 2 lines of 17 characters each.  keyLength always == 34 so keylength/17 == 2
	for x in range(0,keyLength/17):
		lastCharPos=0
		#print a line
		for y in range(0, 17):
			theChar = privkey[(x*17)+y]
			charSize = draw.textsize(theChar, font=font)
			#print charSize
			if y == 0:
				draw.text((startPos[0],startPos[1]+(lineHeight*x)),theChar, font=font, fill=(0,0,0))
				lastCharPos = startPos[0]+charSize[0]+(charDist-charSize[0])
			else:
				draw.text((lastCharPos,startPos[1]+(lineHeight*x)),theChar, font=font, fill=(0,0,0))
				lastCharPos = lastCharPos + charSize[0] + (charDist-charSize[0])


#draw the QR code on the final image
	finalImg.paste(privkeyImg, (125, 560))

#---end the private key qr code generation and drawing section---



#create the divider
	rightMarkText = "Piperwallet.com"


	font = ImageFont.truetype("/usr/share/fonts/ttf/swansea.ttf", 20)

	rightMarkSize = draw.textsize(rightMarkText, font=font)

	rightMarkOrigin = (384-rightMarkSize[0]-10, 10)


	dividerLineImg = Image.open("/home/pi/Printer/dividerline.bmp")
#font = ImageFont.truetype("/home/pi/Helvetica.ttf", 20)
	draw = ImageDraw.Draw(dividerLineImg)

	draw.text(rightMarkOrigin,rightMarkText, font=font, fill=(255,255,255))





#do the actual printing

	printer.printImage(finalImg)

	printer.printChar(privkey[:17]+"\n")
	printer.justify('R')
	printer.printChar(privkey[17:34]+"\n")
	printer.justify('L')
	printer.printChar(privkey[34:]+"\n")

	#print the divider line
	time.sleep(0.4)
	printer.printImage(dividerLineImg)
	
	#print some blank space so we can get a clean tear of the paper
	time.sleep(0.4)
	printer.feed(1)
	time.sleep(0.4)
	printer.feed(1)
	time.sleep(0.4)
	printer.feed(1)





	printer.sleep()      # Tell printer to sleep
	printer.wake()       # Call wake() before printing again, even if reset
	printer.setDefault() # Restore printer to defaults
