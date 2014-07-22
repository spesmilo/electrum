# Class inheritance diagram
#                      
#                      [[QValidator]]          
#                              ^               
#                              |               
#                              |               
#                   [[QSDNNumericValidator]]
# 
# 
# SDN stands for 'standard decimal notation'.  That is not 'normalized Scientific notation'.

from qsdnlocale import *
from PyQt4.QtCore import *

def atleast0(i):
    return i if i >= 0 else 0

""" QSDNNumericValidator limits the number of digits after the decimal
 point and the number of digits before. 
 
  bitcoin                         :  QSDNNumericValidator(8, 8)
  US dollars less than $1,000,000 :  QSDNNumericValidator(6, 2)
  
  
  If use space is true, spaces are added on the left such that the location
  of decimal point remains constant.  Numbers like '10,000.004', '102.126' become 
  aligned.
  Bitcoin amounts:
  
                     '        0.004,3'
                     '       10.4'
                     '      320.0'
                     '        0.000,004'
                     
  U.S. dollar amounts;  
                     dollar = QSDNNumericValidator(6,2)
                     s = '42.1'
                     dollar.validate(s='42.1', 2)   =>  s = '     42.10'
                     s='50000'
                     dollar.toString(s)              => s = ' 50,000.00'
           
                            
"""
class QSDNNumericValidator(QValidator) :
    def __init__(self, maximum_decamals = 1000, maximum_decimals = 1000, use_space = False, parent = None) :
        QValidator.__init__(self, parent)
        # true if we use spaces for justifying the string.
        self.spaced = use_space        
        self.characters_before_decimalPoint = maximum_decamals * 4 // 3
       	self.characters_after_decimalPoint = maximum_decimals * 4 // 3
        self._locale = QSDNLocale(QLocale.system())
        space_part = ' *' if self.spaced else ''
        decimalPoint = QRegExp.escape(QString(self._locale.decimalPoint()))
        groupSeparator = QRegExp.escape(QString(self._locale.groupSeparator()))
        self.proper_re = QRegExp('(' + space_part + \
            '\d{1,3}(' + groupSeparator + '\d{3})*)(' + decimalPoint + '((\d{3}' + groupSeparator + ')*\d{1,3})?)?')
        self.improper_decimal_re = QRegExp('(' + space_part + ')([\d' + groupSeparator + ']*)(' + decimalPoint + '([\d' + groupSeparator + ']*))?')
   
    def decimals(self):
	return self.characters_after_decimalPoint * 3//4
	
    def setDecimals(self, i):
	self.characters_after_decimalPoint = i * 4 // 3
	
    def decamals(self):
    	return self.characters_before_decimalPoint * 3 / 4
    	
    def setDecamals(self, i):
    	self.characters_before_decimalPoint = i * 4 // 3
    
    # Count non-space, non-comma characters: digits and a decimal point up to limit in QString s.    
    def count_occurences(self, s, limit):
    	counter = 0
    	for i in range(0, limit):
    	    if s.at(i)  != QChar(self._locale.groupSeparator()) and s.at(i) != QChar(' '):
    	    	counter += 1
    	return counter;

    # Make it such that the number of characters before the decimal point is self.characters_before_decimalPoint by
    # adding or removing spaces and returning a new position such that this new position will be between the same
    # digits as the position indicated by pos. 
    def correct_white(self, s, pos):
    	whole_part = QRegExp(QString('^ *((\d|') + self._locale.groupSeparator() + ')*)')
    	whole_part.indexIn(s)    	
    	decimalPoint_location = s.indexOf(self._locale.decimalPoint())
    	decimalPoint_location = s.length() if decimalPoint_location == -1 else decimalPoint_location
    	assert(decimalPoint_location in range(0, s.length()+1))
    	needed_white = atleast0(self.characters_before_decimalPoint - whole_part.cap(1).length())
	if self.characters_before_decimalPoint != decimalPoint_location:
	    pos += self.characters_before_decimalPoint - decimalPoint_location if pos != 0 else 0
	    s.replace( QRegExp("^ *"), QString(needed_white*' ') )
	assert(s.indexOf('.') == -1 or s.indexOf('.') == self.characters_before_decimalPoint)
	return pos
    	       	
    # Validates s, by adjusting the position of the commas to be in the correct places and adjusting pos accordingly 
    # as well as space in order to keep decimal points aligned when varying sized numbers are put one above the other.
    def validate(self, s, pos):
    	debug = False
    	if debug:
    	    print 'call to self.validate(%s,%d)' % (s,pos)
    	    print s
    	    print pos * ' ' + '^'
        if s.indexOf('!') != -1:
            self.emit(SIGNAL("bang()"))
            return QValidator.Invalid, pos
        if self.spaced:
            pos = self.correct_white(s, pos)
        if QRegExp("^ *").exactMatch(s):
            return QValidator.Intermediate, pos
        if not self.improper_decimal_re.exactMatch(s):
            return QValidator.Invalid, pos
	if self.proper_re.exactMatch(s):
	    # no need to fix the commas
	    whole_part = self.proper_re.cap(2)
	    fraction_part = self.proper_re.cap(3)
	    if fraction_part.__class__ != QString:
	    	fraction_part = QString("")
	    comma_last = False
	else:
	    pos_inside_spaces = False if pos in range(self.improper_decimal_re.pos(2),s.length()+1) else True	    	     
	    comma_last = s.at(s.length()-1) == self._locale.groupSeparator()
	    after_comma = pos > 0 and pos <= s.length() and s.at(pos-1) == self._locale.groupSeparator()
	    old_count = self.count_occurences(s, pos)
	    if debug:
		print 'digits before this position(%d) is %d' % (pos, old_count)
	    [whole_part, fraction_part] = [self.improper_decimal_re.cap(2), self.improper_decimal_re.cap(4)]
	    whole_part.replace(QString(self._locale.groupSeparator()), '')
	    fraction_part.replace(QString(self._locale.groupSeparator()),'')
	    fraction_part = QString('{:,}'.format(long(str((fraction_part.append('5'))[::-1])))[::-1] if fraction_part != QString('') else '')
	    fraction_part.replace(QRegExp('(,5|5,|5)$'), '')
	    fraction_part.replace(',', self._locale.groupSeparator())
	    if fraction_part != QString(''):
		fraction_part.prepend(self._locale.decimalPoint())
	    whole_part = QString('{:,}'.format(long(str(whole_part))) if whole_part != '' else '0')
	    whole_part.replace(',', self._locale.groupSeparator())
	    s.clear()
	    s.append(self.improper_decimal_re.cap(1)) # the spaces
	    s.append(whole_part)
	    s.append(fraction_part)
	    if comma_last:
		s.append(',')
	    pos = atleast0(self.improper_decimal_re.pos(1)) if pos_inside_spaces else atleast0(self.improper_decimal_re.pos(2))
	    while pos < s.length() and old_count > 0:
		if s[pos] != self._locale.groupSeparator() and s.at(pos) != QChar(' '):
		    old_count -= 1
		if debug:
		    print "(%d,%d)" % (old_count, pos)
		pos += 1
	    if debug:
		print 'digits before this position(%d) is %d' % (pos, self.count_occurences(s, pos))    
	    if after_comma and pos in range(0,s.length()) and s[pos] == self._locale.groupSeparator():
		pos += 1
	    if debug:
		print 'new position is %d' % pos
	    if self.spaced:
		pos = self.correct_white(s, pos)
	    if debug:
		print 'digits before this position(%d) is %d' % (pos, self.count_occurences(s, pos))
		print s
		print pos * ' ' + '^'
		print 'exiting'
	
	if fraction_part.length() > self.characters_after_decimalPoint+1:
	    s.truncate(s.length()-1)
	if comma_last or whole_part.length() > self.characters_before_decimalPoint or fraction_part.length() > 1+self.characters_after_decimalPoint:
	    if debug:
	    	print 'Returning as Intermediate'
	    return QValidator.Intermediate, pos
	else:
	    if debug:
	    	print 'Returning as Acceptable'
	    return QValidator.Acceptable, pos
	    
    def setLocale(self, plocale):
    	self._locale = plocale
    	self.emit(SIGNAL("localeSet"), plocale)

    def locale(self):
    	return self._locale
    	
    def fixup(self, s):
    	print 'fixup(' + s + ') called'
    	dp = s.indexOf('.')
    	if dp != -1 and s.length() - dp - 1 > self.characters_after_decimalPoint:
    	    s.truncate(dp + self.characters_after_decimalPoint)
    	    


