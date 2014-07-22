# Class inheritance diagram
#                      
#           [[QLocale]]
#                ^
#                |
#                |
#          [[QSDNLocale]]
#      
 


import re
import decimal
import string
from decimal import localcontext
from decimal import Decimal as D
try:
    from PyQt4.QtCore import *
    from PyQt4.QtGui import *
except ImportError:
    print "You need to have PyQT installed to run these tests."
    print "If you have pip installed try 'sudo pip install pyqt' if you are on Debian/Ubuntu try 'sudo apt-get install python-qt4'."
    sys.exit(0)

""" 
Improved QLocale class, numeric values will have thousand separators before **and after** the decimal point.  Thousand separators in general will not always be commas but instead will be different according to the locale settings.  In Windows for example, the user can set his thousand separator to whatever character he wants.  Support for converting strings directly to Decimals and from Decimals to strings is included.

Also, numbers are always expressed in standard decimal notation.
"""
class QSDNLocale(QLocale) :
	
	# p_mandatory_decimals becomes _mandatory_decimals
	# p_maximum_decimals becomes _maximum_decimals
	# they control the behavior of toString
	def __init__(self, _name = None, p_mandatory_decimals = D(0), p_maximum_decimals = decimal.Decimal('Infinity')) :
		if _name.__class__ == str or _name.__class__ == QLocale or _name.__class__ == QSDNLocale:
			QLocale.__init__(self, _name)
		elif _name is None:
		    	QLocale.__init__(self)
		else:
		    	QLocale.__init__(self, _name)
		self._mandatory_decimals = p_mandatory_decimals
		self._maximum_decimals = p_maximum_decimals
		
		
	# Convert a single digit number to a QCharacter with the character that represents that single
	# digit number in *this* locale.
	# d must be such that 0 <= d < 10.
	def _toQChar(self, d):
	    assert(0 <= d < 10)
	    d = int(d)
	    return QChar(self.zeroDigit().unicode() + d)
	
	# Like the other to* functions of QLocale as well as this class QSDNLocale, interpret a 
	# a string and parse it and return a Decimal.  The base value is used to determine what base to use.
	# 
	# If base is not set, numbers such as '0777' will be interpreted as octal.  The string '0x33' will
	# be interpreted as hexadecimal and '777' will be interpreted as a decimal.  It is done this way
	# so this works like toLong, toInt, toFloat, etc...
	# Leading and trailing whitespace is ignored.
	def toDecimal(self, s, base = 0):
		comma = self.groupSeparator()
		point = self.decimalPoint()
		if s.__class__ == QChar:
		    code = s.digitValue()
		    if code == -1 and base == 16:
		    	code = QString(10*' '+'abcdef').indexOf(s, 10, Qt.CaseInsensitive)
		    if  code != -1 and (base == 0 or code < base):
		    	return (decimal.Decimal(code), True)
		    return (decimal.Decimal('0'), False)
		# convert s, if it is a str, into a QString
		if s.__class__ == str:
		    s = QString(s)
		# derive the base if not set above.
		try:
		    # here a copy is made, the original s will not be
		    # modified.
		    s = s.trimmed()
		    if base == 0:
			if s.startsWith('0x', Qt.CaseInsensitive):
			    s = s[2:]
			    base = 16
			elif s.startsWith('0'):
			    s = s[1:]
			    base = 8
			else:
			    base = 10
		except:
		    return (0, False)
		v = decimal.Decimal("0")
		shift = decimal.Decimal('0')
		are_there_digits = False
		add_shifts = False
		comma_offset = None
		for c in s:
		    if c == comma:
			if comma_offset == None:
			    comma_offset = 0
			elif comma_offset != 3:
			    return (1, False)
			elif self.numberOptions() & QLocale.RejectGroupSeparator == QLocale.RejectGroupSeparator:
			    return (2, False)
			comma_offset = 0
		    elif c == point:
			comma_offset = 0
			if add_shifts:
			    # two decimal point characters is bad
			    return (v/base**shift, False)
			add_shifts = True
		    else:
			to_add, status = self.toDecimal(QChar(c), base)
			if status:
			    are_there_digits = True
			    v *= base
			    v += to_add
			    if comma_offset != None:
				comma_offset += 1
			    if add_shifts:
				shift += 1
			else:
			    return (v / base**shift, False)	
		v /= base ** shift
		return (v, are_there_digits)
	
			
	# Convert any given Decimal, double, Date, Time, int or long to a string.
	#
	# Numbers are always converted to Standard decimal notation.  That is to say,
	# numbers are never converted to scientifc notation.
	#
	# The way toString is controlled:
	# If passing a decimal.Decimal typed value, the precision is recorded in the 
	# number itself.  So, D('4.00') will be expressed as '4.00' and not '4'.
	# D('4') will be expressed as '4'.
	#
	# When not a decimal.Decimal numbers are created in the following way:
	# Two extra parameters, set during creation of the locale, determines how 
	# many digits will appear in the result of toString().
	#    For example, we have a number like 5.1 and mandatory decimals was set    
	# to 2, toString(5.1) should return '5.10'.  A number like 6 would be '6.00'.
	# A number like 5.104 would depend on the maximum decimals setting, also 
	# set at construction of the locale:
	# _maximum_decimals controls the maximum number of decimals after the decimal point
	# So, if _maximum_decimals is 6 and _mandatory_decimals is 2 then 
	# toString(Decimal('3.1415929')) is '3.141,592'.
	# Notice the number is truncated and not rounded.  
	# The rounding mode is unimportant in the use of this program.
	def toString(self, x, arg2 = None, arg3 = None):	    
	    try:
		xt = D(x).as_tuple()
	    except:
		return QLocale.toString(self, x, arg2, arg3)	    
	    digit_map = [(QString(QChar(a + self.zeroDigit().unicode()))) for a in range(0,10)]
	    st = QString(  ''.join([unicode(digit_map[a]) for a in (xt.digits)])  )
	    if -xt.exponent < st.length():
	    	# The decimal point must go to the right of the most significant digit.
		if xt.exponent < 0:	    	
		    # the decimal point goes next to a digit we already have
		    st.insert(st.length()+xt.exponent, self.decimalPoint())
		else:
		    # We need to add digits before we can write a decimal point
		    # but if you don't have all of the digits for this.
		    # Standard notation is always used here.
		    # For example:
                    # An expression like 3e2 becomes '300' even though, it is 
                    # understood that such a value is not as precise as D(300). 
		    st.append(digit_map[0].repeated(xt.exponent))		    
	    else:
	    	# the digits all belong to places right of the decimal point. 
		st = (digit_map[0]) + QString(self.decimalPoint()) + (digit_map[0]).repeated(-xt.exponent-st.length()) + st
	    dpl = st.indexOf(self.decimalPoint())
	    if x.__class__ != D:
		if dpl == -1 and self._mandatory_decimals:
		    st.append(self.decimalPoint() + digit_map[0].repeated(self._mandatory_decimals))
		if dpl != -1 and st.length() - dpl - 1 < self._mandatory_decimals:
		    st.append(digit_map[0].repeated(self._mandatory_decimals - st.length() + dpl + 1))
		if dpl != -1 and st.length() - dpl - 1 > self._maximum_decimals:
		    st.truncate(dpl+self._maximum_decimals+1)
		if dpl != -1:
		    while st.endsWith(QString(self.zeroDigit())) and st.length()-dpl-1 > self._mandatory_decimals:
			st.chop(1)
	    if (self.numberOptions() & QLocale.OmitGroupSeparator) != QLocale.OmitGroupSeparator:
		dpl = st.indexOf(self.decimalPoint())
		if dpl == -1:
		    dpl = st.length()
		i = dpl+4
		while i < st.length():
		    st.insert(i, self.groupSeparator())
		    i += 4
		i = dpl-3
		while i > 0:
		    st.insert(i, self.groupSeparator())
		    i -= 3	    
	    if xt.sign == 1:
		st.prepend(self.negativeSign())
	    return st
			
	@staticmethod		
	def system() :
	    return QSDNLocale(QLocale.system())
	
	@staticmethod
	def c() :
	    _c = QSDNLocale()
	    _c.setNumberOptions( QLocale.OmitGroupSeparator | QLocale.RejectGroupSeparator )
	    return _c
	    
		
	""" returns a filtered copy of s so that it can be used by the dumber QLocale's to* routines.
	 if QLocale.RejectGroupSeparator is set, this routine wont filter commas.  A decimal point on the end of the number will be removed if 
	 present. """
	def _filtered(self, s):
	    s = QString(s)
	    if s.endsWith(QString(self.decimalPoint())):
		s.chop(1)
	    if QLocale.RejectGroupSeparator & self.numberOptions() != QLocale.RejectGroupSeparator:
		s.remove(self.groupSeparator())
	    return s
	    
    	
	# return a double represented by the string s.
	def toDouble(self, s):
	    return QLocale.toDouble(self, self._filtered(s))
		
	# return a float represented by the string s.
	def toFloat(self, s):
	    return QLocale.toFloat(self, self._filtered(s))
		
	# return a int represented by the string s.
	def toInt(self, s, base = 0):
	    return QLocale.toInt(self, self._filtered(s), base)
       
	# return a long represented by the string s.
	def toLongLong(self, s, base = 0):
	    return QLocale.toLongLong(self, self._filtered(s), base)
	    
	def toShort(self, s, base = 0):
	    return QLocale.toShort(self, self._filtered(s), base)
	    
	# return a uint represented by the string s.
	def toUInt(self, s, base = 0):
	    return QLocale.toUInt(self, self._filtered(s), base)
    
	# return a ulonglong represented by the string s.
	def toULongLong(self, s, base = 0):
	    return QLocale.toULongLong(self, self._filtered(s), base)
	    
	# return a ushort represented by the string s.
	def toUShort(self, s, base = 0):
	    return QLocale.toUShort(self, self._filtered(s), base)
    
