"""
... module:: qsdn
    :platform: Unix, Windows
    :synopsis:  This module allows for parsing, validation and production of numeric literals, written with thousand separators through out the number.  Often underlying system libraries for working with locales neglect to put thousand separators (commas) after the decimal place or they sometimes use scientific notation.  The classes inherit from the Qt classes for making things less complex.
    
    Thousand separators in general will not always be commas but instead will be different according to the locale settings.  In Windows for example, the user can set his thousand separator to any character.  Support for converting strings directly to Decimals and from Decimals to strings is included.
    
    Also, numbers are always expressed in standard decimal notation.
        
    Care has been taken to overload all of the members in a way
    that is consistent with the base class QLocale and QValidator.  
"""

# Class inheritance diagram
#         
#         [[QValidator]]          
#                 ^               
#                 |               
#                 |               
#      [[QSDNNumericValidator]]
# 
# 
# SDN stands for 'standard decimal notation'.  That is not 'normalized Scientific notation'.
import decimal
from decimal import Decimal as D
from PyQt4.QtCore import *
from PyQt4.QtGui import *

class QSDNConverter(QObject) :
    """ 
        
    For a QSDNConverter, locale:  
        To get the Decimal of a string, s, use:
        
        converter = QSDNConverter(8, 8)
        
        (d, ok) = converter.toDecimal(s)
        
        The value d is your decimal, and you should check ok before you trust d.
        
        To get the string representation use:
        
        s = converter.toString(d)
        
    """    
    
    # p_mandatory_decimals becomes _mandatory_decimals
    # p_maximum_decimals becomes _maximum_decimals
    # they control the behavior of toString
    def __init__(self, p_mandatory_decimals = D(0), p_maximum_decimals = decimal.Decimal('Infinity')) :
        """Control how many decimal places are put for units other than Decimal.
        
        Args:
          name (str) the name of the locale: example: "en_US"
        
          p_mandatory_decimals (int or Decimal) the mandatory decimal places required for a number
          
          p_maximum_decimals (int or Decimal) the maximum number of decimals required for a number
        """
        self._mandatory_decimals = p_mandatory_decimals
        self._maximum_decimals = p_maximum_decimals
            
            
    def toDecimal(self, s):
    	"""This creates a decimal representation of s.
    	   
    	   It returns an ordered pair.  The first of the pair is the Decimal number, the second of the pair indicates whether the string had a valid representation of that number.  You should always check the second of the ordered pair before using the decimal returned.
    	       	
           The string is parsed and returns a decimal.  It is always interpreted as decimal.
           Leading and trailing whitespace is ignored.
        """
        s = QString(s).trimmed()
        cl = max(s.indexOf('.'), s.indexOf(','))
        if [ i for i in range(s.length()) if (s[i] == ',' or s[i] == '.') and i % 4 != cl % 4] != []:
	    return (0, False)
        xs = str(s.replace( QString(','), '' ))
        try:
            d = D(xs)
            return (d, True)
	except:
	    return (0, False)
    

    def toString(self, x):
    	"""    Convert any given Decimal to a string.
    
        Numbers are always converted to Standard decimal notation.  That is to say,
        numbers are never converted to scientifc notation.
        
        The way toString is controlled:
        If passing a decimal.Decimal typed value, the precision is recorded in the 
        number itself.  So, D('4.00') will be expressed as '4.00' and not '4'.
        D('4') will be expressed as '4'.
        
        When a number passed is NOT a Decimal, numbers are created in the following way:
        Two extra parameters, set during creation of the locale, determines how 
        many digits will appear in the result of toString().
        For example, we have a number like 5.1 and mandatory decimals was set    
        to 2, toString(5.1) should return '5.10'.  A number like 6 would be '6.00'.
        A number like 5.104 would depend on the maximum decimals setting, also 
        set at construction of the locale:
        _maximum_decimals controls the maximum number of decimals after the decimal point
        So, if _maximum_decimals is 6 and _mandatory_decimals is 2 then 
        toString(Decimal('3.1415929')) is '3.141,592'.
        Notice the number is truncated and not rounded.  
        Consider rounding a copy of the number before displaying.
        """        	
        if x.__class__ != D:
            return None
        st = QString(str(x))
	dpl = st.indexOf('.')
	if dpl == -1:
	    dpl = st.length()
	i = dpl+4
	while i < st.length():
	    st.insert(i, ',')
	    i += 4
	i = dpl-3
	while i > 0:
	    st.insert(i, ',')
	    i -= 3
        return st
                    
    
class QSDNNumericValidator(QValidator) :
    """ QSDNNumericValidator limits the number of digits after the decimal
     point and the number of digits before. 
     
      bitcoin                         :  QSDNNumericValidator(8, 8)
      US dollars less than $1,000,000 :  QSDNNumericValidator(6, 2)
                                                                                                    
      U.S. dollar amounts;  
                         dollar = QSDNNumericValidator(6,2)
                         s = '42.1'
                         dollar.validate(s='42.1', 2)   =>  s = '42.10'
                         s='50000'
                         dollar.toString(s)              => s = '50,000.00'
               
                                
    """                                                                                              
    def __init__(self, maximum_decamals = 1000, maximum_decimals = 1000, not_used = False, parent = None) :
        QValidator.__init__(self, parent)
        # true if we use spaces for justifying the string.
        self.characters_before_decimalPoint = maximum_decamals * 4 // 3
       	self.characters_after_decimalPoint = maximum_decimals * 4 // 3
        self._converter = QSDNConverter(0, maximum_decimals)
        self._locale = QLocale.c()
        self.improper_decimal_re = QRegExp('([\d,]*)(\.([\d,]*))?')
    
    # Count non-space, non-comma characters: digits and a decimal point up to limit in QString s.    
    def _count_occurences(self, s, limit):
    	counter = 0
    	for i in range(0, limit):
    	    if s.at(i) != QChar(',') and s.at(i) != QChar(' '):
    	    	counter += 1
    	return counter;
    	       	
    def validate(self, s, pos):
	""" Validates s, by adjusting the position of the commas to be in the correct places and adjusting pos accordingly.
	"""
        if s.indexOf('!') != -1:
            self.emit(SIGNAL("bang()"))
            return QValidator.Invalid, pos
        if not self.improper_decimal_re.exactMatch(s):
            return QValidator.Invalid, pos
           
	comma_last = s.at(s.length()-1) == self._locale.groupSeparator()
	after_comma = pos > 0 and pos <= s.length() and s.at(pos-1) == self._locale.groupSeparator()
	old_count = self._count_occurences(s, pos)
	theres_no_dot = s.indexOf('.') == -1
	try:
	    ns = self._converter.toString(D(str(s.replace(',', ''))))
	except:
	    return QValidator.Intermediate, pos
	if theres_no_dot:
	    ns.replace('.','')
	elif ns.indexOf('.') == -1:
	    ns += '.'
	s.clear()
	s.append(ns)
	if comma_last:
	    s.append(',')
	pos = 0
	while pos < s.length() and old_count > 0:
	    if s[pos] != self._locale.groupSeparator():
		old_count -= 1
	    pos += 1
	if after_comma and pos in range(0,s.length()) and s[pos] == self._locale.groupSeparator():
	    pos += 1
	if s.indexOf('.') == -1:
	    if self.characters_before_decimalPoint < s.length():
		return QValidator.Invalid, pos
	else:
	    if s.length() - s.indexOf('.') - 1 > self.characters_after_decimalPoint \
                           or \
	       s.indexOf('.') > self.characters_before_decimalPoint:
	    	return QValidator.Invalid, pos
	if comma_last:
	    return QValidator.Intermediate, pos
	else:
	    return QValidator.Acceptable, pos
