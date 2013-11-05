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

class MyQLocale(QLocale) :
    	# Return true if c is a digit for *this* locale.
	def isDigit(self, c, base):
	    c = QChar(c)
	    if base == 0:
	        base = 10
	    status, d = toDecimal(self, c, base)
	    return status
	
	# Convert a single digit number to a QCharacter with the character that represents that single
	# digit number in *this* locale.
	# d must be such that 0 <= d < 10.
	def toQChar(self, d):
	    assert(0 <= d < 10)
	    d = int(d)
	    return QChar(self.zeroDigit().unicode() + d)
	
	# Like the other to* functions of QLocale as well as this class MyQLocale, interpret a 
	# a string and parse it and return a Decimal.  The base value is used to determine what base to use.
	# 
	# If base is not set, numbers such as '0777' will be interpreted as octal.  The string '0x33' will
	# be interpreted as hexadecimal.  But '777' will be interpreted as a decimal.
	# Leading and trailing whitespace is ignored.
	def toDecimal(self, s, base = 0):
		v = decimal.Decimal("0")
		comma = self.groupSeparator()
		point = self.decimalPoint()
		if s.__class__ == QChar:
		    code = s.unicode()
		    if self.zeroDigit().unicode() <= code < self.zeroDigit().unicode() + 10:
		        answer = code - (self.zeroDigit()).unicode()
		        return (True, decimal.Decimal(answer))
		    elif QChar('a').unicode() <= (code|32) <= QChar('f').unicode():
		        return (True, decimal.Decimal(code - QChar('a').unicode()+10))
		    return (False, decimal.Decimal('0'))
		# convert s, if it is a str, into a QString
		if s.__class__ == str:
			s = QString(s)
		try:
		    	s = s.trimmed()
			if base == 0:
				if s[0] == QChar('0'):
					if s[1] == QChar('x'):
						s = s[2:]
						base = 16
					else:
						s = s[1:]
						base = 8
				else:
					base = 10
		except:
			return (False,0)
		shift = decimal.Decimal('0')
		add_shifts = False
		digit_count = None
		for c in s:
			c = c.toLower()
			if c == comma:
				if digit_count == None:
					digit_count = 0
				elif digit_count != 3:
					return (False,0)
				digit_count = 0
				pass
			elif c == point:
				digit_count = 0
				if add_shifts:
					# two decimal point characters is bad
					return (False,v/base**shift)
				add_shifts = True
			else:
				status, to_add = self.toDecimal(QChar(c))
				if status:
					v *= base
					v += to_add
					if digit_count != None:
						digit_count += 1
					if add_shifts:
						shift += 1
				else:
					return (False,v / base**shift)
			
		v /= base ** shift
		if digit_count is None:
		    return (False,v)
		return (True,v)
			
			
	# Convert any given Decimal, double, int or long to a string.
	# Caution: Only Decimal numbers will necessarily 
	# get thousand separators in their string representation.
	#
	# The way toString is controlled:  
	# self.mandatory_decimals controls the number 
	# of decimals that are always present.  So toString(Decimal('4')) is '4.00' when
	# mandatory_decimals is 2.  
	# 
	# maximum_decimals controls the maximum number of decimals after the decimal point
	# So, if maximum_decimals is 6 and mandatory_decimals is 2 then toString(Decimal('3.1415929')) is '3.141592'.
	# Notice the number is truncated and not rounded.  
	# The rounding mode is unimportant in the use of this program.
	def toString(self, v) :	
		if v.__class__.__name__ == 'Decimal':
			comma = self.groupSeparator()
			point = self.decimalPoint()
			os = QString("")
			context = decimal.getcontext()
			this_error = v * 10**-decimal.Decimal(context.prec)
			if (v < 0):
				os = QString("-")
				v = -v
			exp = 0
			power10_exp = decimal.Decimal(1)
			while 10*power10_exp < v:
				#print "10*10**exp = %d, v is %f " % (10*power10_exp, v)
				power10_exp *= 10
				exp+=1
			assert(v < 10*power10_exp)
			# add the digits and commas up to the decimal point.
			limit = int(context.prec)
			while exp > 0:
				#print "string is %s, exp = %d " % (os, exp)
				os += self.toQChar(int(v//power10_exp) % 10)
				if (exp % 3 == 0):
					os += comma
				exp-=1
				power10_exp //= 10
				limit-=1
			
			os += self.toQChar(int(v) % 10)
			# is there are fraction part?
			dv = v - int(v)
			if self.mandatory_decimals != 0 or (this_error <= v and dv != 0 and limit > 1):
				# now do what comes after the decimal point
				os += point
				limit -= 1
				decimal_count = 0
				while decimal_count < self.maximum_decimals and ((decimal_count < self.mandatory_decimals) or (limit > 1 and dv != 0)):
					if exp != 0 and exp % 3 == 0:
					    os += comma
					digit = int(10 * dv)
					os += self.toQChar(digit)
					v *= 10
					v -= digit
					dv = (v - int(v))
					exp -= 1
					limit -= 1
					decimal_count += 1
				
			return os
		else:
			return QLocale.toString(self, v)
			
	@staticmethod		
	def system() :
	    return MyQLocale(QLocale.system())
	    	
	def __init__(self, _name) :
		if _name.__class__ == str or _name.__class__ == QLocale:
			QLocale.__init__(self, _name)
		self.mandatory_decimals = 0
		self.maximum_decimals = decimal.Decimal('Infinity')
		

class MyQDoubleValidator(QDoubleValidator) :
	def __init__(self, parent = None ):
		QDoubleValidator.__init__(self, parent)
		loc = MyQLocale(QLocale.system())
		self.locale = loc
		self.decimalPoint = loc.decimalPoint()
		self.groupSeparator = loc.groupSeparator()
		
#	def __init__(self, bottom, top, decimals, parent ):
#		QDoubleValidator.__init__(self, bottom, top, decimals, parent)
	
	def validate(self, s, pos):
            #print "MyQDoubleValidator validating " + s
            assert(s.__class__ == QString)            
            decimalPoint = QChar(self.locale.decimalPoint())
            groupSeparator = QChar(self.locale.groupSeparator())
            print s
            if s.isEmpty():            
                    return QValidator.Intermediate, pos
            #print 'here'
            if 0 <= pos-1 < s.length():
                    this_character = QChar(s[pos-1])
            else:
                    pos = s.length()-1
                    this_character = QChar(s[s.length()-1])
            if  this_character != decimalPoint and this_character != groupSeparator and \
                    not QChar(this_character).isDigit():
                    return QValidator.Invalid, pos
            del this_character
            #print 'here too'
            decimalPoint_location = s.indexOf(decimalPoint)
            # disallow two decimal points          
            if s.indexOf(decimalPoint, decimalPoint_location + 1) != -1:
                    return QValidator.Invalid, pos
            # when there's no decimal place, set the position of it to
            # the position after the last character in the string.  This
            # way we handle integers with no decimal point at the end 
            # transparently.
            #print 'here as well'
            if decimalPoint_location == -1:
                    decimalPoint_location = s.length()
            # fix up the commas after the decimal point.
            k = decimalPoint_location + 1
            dc = 0
            while k < s.length():
                    if s[k] == groupSeparator:
                            if dc!=3:
                                    if k <= pos:
                                            pos -= 1
                                    s = s.remove(k, 1)
                            else:
                                    dc=0
                                    k=k+1
                    else:
                            dc=dc+1
                            if dc == 4:
                                    if k <= pos:
                                            pos += 1
                                    s = s.insert(k, groupSeparator)
                                    dc = 0
                            k=k+1
            # fix up the commas before the decimal point.
            k = decimalPoint_location - 1
            dc = 0
            while k >= 0:
                    if dc != 3 and s[k] == groupSeparator:
                            while k < s.length() and s[k] == groupSeparator:
                                    s = s.remove(k, 1)
                                    if k <= pos:
                                            pos -= 1
                    elif s[k] == groupSeparator:
                            dc=0
                    else:
                            dc=dc+1
                            if dc == 4:
                                    if k <= pos:
                                            pos += 1
                                    s = s.insert(k+1, groupSeparator)
                                    dc = 1        
                    k=k-1
            del k
            del dc
            if (not s.isEmpty()) and s[0] == self.groupSeparator or \
            s[s.length()-1] == self.groupSeparator:
                    return QValidator.Intermediate, pos
            return QValidator.Acceptable, pos
            
	def test(self, cases):
		for case in cases:
			(control, old_string) = case
			control = (control[0], QString(control[1]))
			new_string = QString(old_string)
			status, pos = self.validate(new_string,len(old_string))
			test_equal("validation test", control, (status, new_string) ) 


class CommaSeparatedSpacedQDoubleValidator(QDoubleValidator) :
    def __init__(self, maximum_decamals, maximum_decimals, use_space = False, parent = None) :
		QDoubleValidator.__init__(self, parent)
		loc = MyQLocale(QLocale.system())
		self.locale = loc
		self.decimalPoint = loc.decimalPoint()
		self.groupSeparator = loc.groupSeparator()
		self.maximum_decamals = maximum_decamals
		self.maximum_decimals = maximum_decimals
		self.spaced = use_space
	
    def validate(self, s, pos):
            assert(s.__class__ == QString)             
            decimalPoint = QChar(self.locale.decimalPoint())
            groupSeparator = QChar(self.locale.groupSeparator())
            if s.indexOf('!') != -1:
            	s[0] = '!'
            	s.remove(1,s.length()-1)
            	return QValidator.Acceptable, 1
            if s.isEmpty():       
                    return QValidator.Intermediate, pos 
            first_non_space_location = 0
            while first_non_space_location < s.length() and s[first_non_space_location] == ' ':
                    first_non_space_location+=1
            if first_non_space_location == s.length():
                return QValidator.Intermediate, pos
            decimalPoint_location = s.indexOf(decimalPoint)
            if s.indexOf(decimalPoint, decimalPoint_location + 1) != -1:
                return QValidator.Invalid, pos
            if      decimalPoint_location    !=    -1       and (  decimalPoint_location == 0   or   (not QChar(s[decimalPoint_location-1]).isDigit())  ):
            	s.insert(decimalPoint_location, self.locale.zeroDigit())
            	if pos > decimalPoint_location:
            	    pos += 1
            	decimalPoint_location += 1
            if decimalPoint_location == -1:
                decimalPoint_location = s.length()
            assert 0 <= decimalPoint_location <= s.length()
            space_change = 4*self.maximum_decamals//3 - decimalPoint_location
            #print "space change is %d " % space_change
            if decimalPoint_location < self.maximum_decamals:
                s.prepend(space_change * ' ')
	    elif decimalPoint_location > self.maximum_decamals:
	    	s.remove(0, -space_change)
            first_non_space_location += space_change
            if pos >= decimalPoint_location:
                    pos += space_change
            decimalPoint_location += space_change
            if not ( 0 <= decimalPoint_location <= s.length() ):
            	# this means the there are too many decamals for this currency.
           	return QValidator.Invalid, pos
            if decimalPoint_location != s.length():
            	if decimalPoint_location != 4*self.maximum_decamals//3:
            	    print "decimalPoint location = %d != %d" % (decimalPoint_location, self.maximum_decamals)
            	    assert False
            #print "MID STRING(s) = >>>"+  s.mid(first_non_space_location) + "<<<" 
            for this_character in s.mid(first_non_space_location):
            	this_character = QChar(this_character)
                if this_character not in [ decimalPoint ,  groupSeparator ]  and not this_character.isDigit() :
                    print "Character in string is a bad character: \'" + str(this_character) + "\'"
                    return QValidator.Invalid, pos
            # when there's no decimal place, set the position of it to
            # the position after the last character in the string.  This
            # way we handle integers with no decimal point at the end 
            # transparently.
            #print 'here as well'
            if decimalPoint_location != s.length():
                    assert s[decimalPoint_location] == '.'
            # fix up the commas after the decimal point.
            k = decimalPoint_location + 1
            dc = 0
            while k < s.length():
                    if s[k] == groupSeparator:
                            if dc!=3:
                                    if k <= pos:
                                            pos -= 1
                                    s = s.remove(k, 1)
                            else:
                                    dc=0
                                    k=k+1
                    else:
                            dc=dc+1
                            if dc == 4:
                                    if k <= pos:
                                            pos += 1
                                    s = s.insert(k, groupSeparator)
                                    dc = 0
                            k=k+1
            # fix up the commas before the decimal point.
            k = decimalPoint_location - 1
            dc = 0
            while k >= first_non_space_location:
                    if dc != 3 and s[k] == groupSeparator:
                            while k < s.length() and s[k] == groupSeparator:
                                    s = s.remove(k, 1)
                                    s.prepend(' ')
                                    if k <= pos:
                                            pos -= 1
                    elif s[k] == groupSeparator:
                            dc=0
                    else:
                            dc=dc+1
                            if dc == 4:
                                    if k <= pos:
                                            pos += 1
                                    s = s.insert(k+1, groupSeparator)
                                    if s[0] == ' ':
                                    	s.remove(0, 1)
                                    dc = 1
                    k=k-1
            del k
            del dc
            if first_non_space_location - decimalPoint_location > 4*self.maximum_decimals//3:
                return QValidator.Invalid, pos
            if s.length() - decimalPoint_location - 1 > 4*self.maximum_decimals//3:
            	return QValidator.Invalid, pos
            if (not s.isEmpty()) and s[0] == self.groupSeparator or \
            s[s.length()-1] == self.groupSeparator:
                    return QValidator.Intermediate, pos
            return QValidator.Acceptable, pos
    def test(self, cases):
		for case in cases:
			(control, old_string) = case
			control = (control[0], QString(control[1]))
			new_string = QString(old_string)
			status, pos = self.validate(new_string,len(old_string))
			test_equal("validation test", control, (status, new_string) ) 

# CryptoCurrency Validator limits the number of digits after the decimal
# point and the number of digits before.  Unlike real numbers, coinage
# is restricted in this way.
class CryptoCurrencyValidator(MyQDoubleValidator) :
	# bitcoin :  CryptoCurrencyValidator(8, 8)
    def __init__(self, maximum_decamals, maximum_decimals, use_space = False) :
        MyQDoubleValidator.__init__(self)
        self.maximum_decamals = maximum_decamals
        self.maximum_decimals = maximum_decimals
        # true if we use spaces for justifying the string.
        self.spaced = use_space
        
    def validate(self, s, pos):
        assert(s.__class__ == QString)   
        this_s = s
    	#print "Validating: " +  '*'+ s+ '*'
        decimalPoint = self.locale.decimalPoint()
        groupSeparator = self.locale.groupSeparator()
        #print "pos = " + self.locale.toString(pos)
        first_non_space_location = 0
        while s[first_non_space_location] == ' ':
        	first_non_space_location+=1
        decimalPoint_location = s.indexOf(decimalPoint)
    	#print "Passing \'" + s + "\' to MyQDoubleValidator"
    	qdouble_pos = pos
        status, qdouble_pos = MyQDoubleValidator.validate(self, s, qdouble_pos)
        #print "Finished"
        if pos >= first_non_space_location:
        	pos += qdouble_pos - pos
        #print "pos = " + self.locale.toString(pos)
        if decimalPoint_location == -1:
            decimalPoint_location = s.length()
        if decimalPoint_location > self.maximum_decamals * 4 // 3:
            return QValidator.Invalid, pos
        if s.length() - decimalPoint_location - 1 > self.maximum_decimals * 4 // 3:
            return QValidator.Invalid, pos
        # here add space needed to        
        if self.spaced:
        	# must not use leftJustified() or left() because we need to modify
        	# s in place.
        	characters_before_decimalPoint = self.maximum_decamals * 4 // 3
        	spaces_added = 0
        	if s.indexOf(decimalPoint) != -1:
        		while (s.indexOf(decimalPoint) < characters_before_decimalPoint)\
        										and\
        										spaces_added <= characters_before_decimalPoint:
        			s.prepend(' ')
        			if pos > 0:
        				pos += 1
        			spaces_added += 1
        	else:
        		while characters_before_decimalPoint > s.length():
        			s.prepend(' ')
        			if pos > 0:
        				pos+=1
        			spaces_added +=1
        	
        assert(s is this_s)	
        return status, pos


class test_case :
	def __init__(self) :
		self.val = 0
		self.lit = "0"
	
	def __init__(self, val, lit) :
		self.val = decimal.Decimal( val )
		self.lit = lit
		
	def __str__(self):
		return "(" + self.val.__str__(self.val) + ", " + self.lit + ")"
	
	def toString(self):
		return __str__(self)


test_stats = [ 0, 0 ]
verbose = False
def test_summary():
	print "%7d tests succeded.\n%7d tests failed." % tuple(test_stats)	

def test_equal(name, control, test):
	if test.__class__ != control.__class__:
		if {control.__class__, test.__class__} == {QString, str}:
			test = QString(test)
			control = QString(control)
	if (test == control):
		if verbose:
			try:
				print "Test " + name + " successful for " + str(test)
			except:
				print "Test " + name + " successful."
		test_stats[0] += 1
	else:
		try:
			print "Test " + name + " failed.  Expected " + str(control) + " but got " + str(test)
		except:
			print "Test " + name + " failed." 
		test_stats[1] += 1
		
if __name__ == '__main__':
		
		context = decimal.getcontext()
		context.prec = 8+7
		decimal.setcontext(context)
		tests = ( test_case(decimal.Decimal("43112279.75467"), "43,112,279.754,67"), test_case(decimal.Decimal("0.0101020204"),"0.010,102,020,4"),
			test_case(decimal.Decimal("0.00000001"), "0.000,000,01")
			)
		locale = MyQLocale("en")
		QLocale.setDefault(locale)
		for c in tests:
			test_equal( "Test case %s" % c.lit, QString(c.lit), locale.toString(c.val))
		
		if verbose:
			try:
				spanishlocale = MyQLocale("es_ES")
				print "Using %s locale" % spanishlocale.name()
				for c in tests:
					print "The value %s is %s" % (c.lit, spanishlocale.toString(c.val))
			except:
				print "Could not get a Spanish locale to show you what they look like.  too bad."
				
			try:
				koreanlocale = MyQLocale("kr")
				print "Using %s locale" % koreanlocale.name()
				for c in tests:
					print "The value %s is %s" % (c.lit, koreanlocale.toString(c.val))
			except:
				print "Could not get a Korean locale to show you what they look like.  too bad."
				
			try:
				clocale = MyQLocale("C")
				print "Using %s locale" % clocale.name()
				for c in tests:
					print "The value %s is %s" % (c.lit, clocale.toString(c.val))
			except:
				print "Could not get the C locale to show you what they look like.  too bad."
			
			
			print "The locale your system is using is %s" % QLocale.system().name()
			
		(good,d) = locale.toDecimal(QString("7,423.231,123"))
		test_equal("7 billion #1", True, good)
		test_equal("7 billion #2", decimal.Decimal("7423.231123"), d )
		test_equal("7 billion #3", "7,423.231,123", locale.toString(d) )
		
		(good,d) = locale.toDecimal(QString("0xB,ADF,00D"))
		test_equal("0xB,ADF,00D #1", True, good)
		test_equal("0xB,ADF,00D #2", decimal.Decimal("195948557"), d)
		test_equal("5/16 hex #1", (True, decimal.Decimal("0.3125")), locale.toDecimal("0x0.5")) # 5/16
		test_equal("5/16 hex #2", (True, decimal.Decimal("0.3125")), locale.toDecimal("0.5", 16)) # 5/16
		test_equal("1 1/4 octal #1", (True, D("1.25")), locale.toDecimal("01.2"))  # 1 1/4
		test_equal("1 1/4 octal #2", (True, D("1.25")), locale.toDecimal("1.2", 8))  # 1 1/4
		test_equal("1 1/5 decimal #1", (True, D("1.2")), locale.toDecimal("01.2", 10))	# 1 1/5
		test_equal("1 1/5 decimal #2", (True, D("1.2")), locale.toDecimal("1.2"))	# 1 1/5
		test_equal("4+2+1/4+1/8 binary", (True, D("6.375")), locale.toDecimal("110.011", 2))
		context.prec = 4
		locale.mandatory_decimals = 2
		locale.maximum_decimals = 2
		test_equal("12 dollars", "12.00", locale.toString(decimal.Decimal("12.00001")))
		test_equal("rubbles", "3,379.70", locale.toString(decimal.Decimal("3379.70")) )
		test_equal( "cny", "636.40", locale.toString(decimal.Decimal("636.40")))
		test_equal( "GBP", "67.56", locale.toString(decimal.Decimal("67.56")))
		test_equal( "USD", "103.00", locale.toString(decimal.Decimal("103.00")))
		context.prec = 30
		decimal.setcontext(context)
		locale.maximum_decimals = 5
		test_equal( "1/3", "0.333,33", locale.toString(decimal.Decimal("1")/3))
		test_equal( "1/2", "0.50", locale.toString(decimal.Decimal("1")/2))
		
		validator = MyQDoubleValidator(None)
		
		if verbose and validator.validate(QString("0.003,2"), 0):
			print "0.003,2 tests as valid: good."
		validator.test( [  \
				((QValidator.Acceptable, "0.003,4"), "0.0034"), \
				((QValidator.Acceptable, "0.001,423"), "0.001,423"), \
		((QValidator.Acceptable, "0.003,412,3"), "0.003,412,3"), \
		((QValidator.Acceptable, "123,456,789"), "123456789"), \
		((QValidator.Acceptable, "0.013,410"), "0.013410"), \
		((QValidator.Intermediate, "0.123,"), "0.123,"), \
		((QValidator.Acceptable, ".42"), ".42"),
		((QValidator.Invalid, "0123.12.3"), "0123.12.3") ] )
		# simulate someone entering 17,777,216
		(status, pos) = validator.validate(QString(""), 0)
		test_equal("Validate validate partial string #0", QValidator.Intermediate, status)
		s = "1"
		for this_length in range(1, len("17,777,216")):
			s = "17,777,216"[0:this_length]
			qs = QString(s)
			(status, pos) = validator.validate(qs, len(s))
			(status, value) = locale.toDecimal(s, 10)
			test_equal("Validator validates partial string #%d" % this_length , True, status != QValidator.Invalid)
			
			
		# Okay try some really exotic locales:
		egyptian = MyQLocale( QLocale( QLocale.Arabic, QLocale.Egypt ) )
		test_equal( "Egyptian PI 5 digits", QString(u'\u0663\u066b\u0661\u0664\u0661\u066c\u0666'), egyptian.toString( D('3.1416') ) )
		
		validator = CommaSeparatedSpacedQDoubleValidator(8, 8, False)
		
		if verbose and validator.validate(QString("0.003,2"), 0):
			print "0.003,2 tests as valid: good."
		validator.test( [  \
				((QValidator.Acceptable, ' ' * 9 + "0.003,4"), "0.0034"), \
				((QValidator.Acceptable, ' ' * 9 + "0.001,423"), "0.001,423"), \
		((QValidator.Acceptable, ' ' * 9 + "0.003,412,3"), ' ' * 9 + "0.003,412,3"), \
		((QValidator.Invalid, "123456789"), "123456789"), \
		((QValidator.Acceptable,  ' ' * 9 + "0.013,410"), "0.013410"), \
		((QValidator.Intermediate,  ' ' * 9 + "0.123,"),"0.123,"), \
		((QValidator.Acceptable, ' ' * 9 + "0.42"), "  .42"),
		((QValidator.Invalid, "0123.12.3"), "0123.12.3") ] )
		# simulate someone entering 17,777,216
		(status, pos) = validator.validate(QString(""), 0)
		test_equal("Validate validate partial string #0", QValidator.Intermediate, status)
		s = "1"
		for this_length in range(1, len("17,777,216")):
			s = "17,777,216"[0:this_length]
			qs = QString(s)
			(status, pos) = validator.validate(qs, len(s))
			(status, value) = locale.toDecimal(s, 10)
			test_equal("Validator validates partial string #%d" % this_length , True, status != QValidator.Invalid)
			test_equal("Validator makes integer %s=>\'%s\' exactly 10 characters long ." % (s, str(qs)), 10, qs.length()) 
			
			
		test_summary()
