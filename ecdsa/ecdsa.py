#! /usr/bin/env python
"""
Implementation of Elliptic-Curve Digital Signatures.

Classes and methods for elliptic-curve signatures:
private keys, public keys, signatures,
NIST prime-modulus curves with modulus lengths of
192, 224, 256, 384, and 521 bits.

Example:

  # (In real-life applications, you would probably want to
  # protect against defects in SystemRandom.)
  from random import SystemRandom
  randrange = SystemRandom().randrange

  # Generate a public/private key pair using the NIST Curve P-192:

  g = generator_192
  n = g.order()
  secret = randrange( 1, n )
  pubkey = Public_key( g, g * secret )
  privkey = Private_key( pubkey, secret )

  # Signing a hash value:
 
  hash = randrange( 1, n )
  signature = privkey.sign( hash, randrange( 1, n ) )

  # Verifying a signature for a hash value:

  if pubkey.verifies( hash, signature ):
    print "Demo verification succeeded."
  else:
    print "*** Demo verification failed."

  # Verification fails if the hash value is modified:

  if pubkey.verifies( hash-1, signature ):
    print "**** Demo verification failed to reject tampered hash."
  else:
    print "Demo verification correctly rejected tampered hash."

Version of 2009.05.16.

Revision history:
      2005.12.31 - Initial version.
      2008.11.25 - Substantial revisions introducing new classes.
      2009.05.16 - Warn against using random.randrange in real applications.
      2009.05.17 - Use random.SystemRandom by default.

Written in 2005 by Peter Pearson and placed in the public domain.
"""


import ellipticcurve
import numbertheory
import random



class Signature( object ):
  """ECDSA signature.
  """
  def __init__( self, r, s ):
    self.r = r
    self.s = s



class Public_key( object ):
  """Public key for ECDSA.
  """

  def __init__( self, generator, point ):
    """generator is the Point that generates the group,
    point is the Point that defines the public key.
    """
    
    self.curve = generator.curve()
    self.generator = generator
    self.point = point
    n = generator.order()
    if not n:
      raise RuntimeError, "Generator point must have order."
    if not n * point == ellipticcurve.INFINITY:
      raise RuntimeError, "Generator point order is bad."
    if point.x() < 0 or n <= point.x() or point.y() < 0 or n <= point.y():
      raise RuntimeError, "Generator point has x or y out of range."


  def verifies( self, hash, signature ):
    """Verify that signature is a valid signature of hash.
    Return True if the signature is valid.
    """

    # From X9.62 J.3.1.

    G = self.generator
    n = G.order()
    r = signature.r
    s = signature.s
    if r < 1 or r > n-1: return False
    if s < 1 or s > n-1: return False
    c = numbertheory.inverse_mod( s, n )
    u1 = ( hash * c ) % n
    u2 = ( r * c ) % n
    xy = u1 * G + u2 * self.point
    v = xy.x() % n
    return v == r
    


class Private_key( object ):
  """Private key for ECDSA.
  """

  def __init__( self, public_key, secret_multiplier ):
    """public_key is of class Public_key;
    secret_multiplier is a large integer.
    """
    
    self.public_key = public_key
    self.secret_multiplier = secret_multiplier

  def sign( self, hash, random_k ):
    """Return a signature for the provided hash, using the provided
    random nonce.  It is absolutely vital that random_k be an unpredictable
    number in the range [1, self.public_key.point.order()-1].  If
    an attacker can guess random_k, he can compute our private key from a
    single signature.  Also, if an attacker knows a few high-order
    bits (or a few low-order bits) of random_k, he can compute our private
    key from many signatures.  The generation of nonces with adequate
    cryptographic strength is very difficult and far beyond the scope
    of this comment.

    May raise RuntimeError, in which case retrying with a new
    random value k is in order.
    """

    G = self.public_key.generator
    n = G.order()
    k = random_k % n
    p1 = k * G
    r = p1.x()
    if r == 0: raise RuntimeError, "amazingly unlucky random number r"
    s = ( numbertheory.inverse_mod( k, n ) * \
          ( hash + ( self.secret_multiplier * r ) % n ) ) % n
    if s == 0: raise RuntimeError, "amazingly unlucky random number s"
    return Signature( r, s )



def int_to_string( x ):
  """Convert integer x into a string of bytes, as per X9.62."""
  assert x >= 0
  if x == 0: return chr(0)
  result = ""
  while x > 0:
    q, r = divmod( x, 256 )
    result = chr( r ) + result
    x = q
  return result


def string_to_int( s ):
  """Convert a string of bytes into an integer, as per X9.62."""
  result = 0L
  for c in s: result = 256 * result + ord( c )
  return result


def digest_integer( m ):
  """Convert an integer into a string of bytes, compute
     its SHA-1 hash, and convert the result to an integer."""
  #
  # I don't expect this function to be used much. I wrote
  # it in order to be able to duplicate the examples
  # in ECDSAVS.
  #
  from hashlib import sha1
  return string_to_int( sha1( int_to_string( m ) ).digest() )


def point_is_valid( generator, x, y ):
  """Is (x,y) a valid public key based on the specified generator?"""

  # These are the tests specified in X9.62.

  n = generator.order()
  curve = generator.curve()
  if x < 0 or n <= x or y < 0 or n <= y:
    return False
  if not curve.contains_point( x, y ):
    return False
  if not n*ellipticcurve.Point( curve, x, y ) == \
     ellipticcurve.INFINITY:
    return False
  return True



# NIST Curve P-192:
_p = 6277101735386680763835789423207666416083908700390324961279L
_r = 6277101735386680763835789423176059013767194773182842284081L
# s = 0x3045ae6fc8422f64ed579528d38120eae12196d5L
# c = 0x3099d2bbbfcb2538542dcd5fb078b6ef5f3d6fe2c745de65L
_b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1L
_Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012L
_Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811L

curve_192 = ellipticcurve.CurveFp( _p, -3, _b )
generator_192 = ellipticcurve.Point( curve_192, _Gx, _Gy, _r )


# NIST Curve P-224:
_p = 26959946667150639794667015087019630673557916260026308143510066298881L
_r = 26959946667150639794667015087019625940457807714424391721682722368061L
# s = 0xbd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5L
# c = 0x5b056c7e11dd68f40469ee7f3c7a7d74f7d121116506d031218291fbL
_b = 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4L
_Gx =0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21L
_Gy = 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34L

curve_224 = ellipticcurve.CurveFp( _p, -3, _b )
generator_224 = ellipticcurve.Point( curve_224, _Gx, _Gy, _r )

# NIST Curve P-256:
_p = 115792089210356248762697446949407573530086143415290314195533631308867097853951L
_r = 115792089210356248762697446949407573529996955224135760342422259061068512044369L
# s = 0xc49d360886e704936a6678e1139d26b7819f7e90L
# c = 0x7efba1662985be9403cb055c75d4f7e0ce8d84a9c5114abcaf3177680104fa0dL
_b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bL
_Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296L
_Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5L

curve_256 = ellipticcurve.CurveFp( _p, -3, _b )
generator_256 = ellipticcurve.Point( curve_256, _Gx, _Gy, _r )

# NIST Curve P-384:
_p = 39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319L
_r = 39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643L
# s = 0xa335926aa319a27a1d00896a6773a4827acdac73L
# c = 0x79d1e655f868f02fff48dcdee14151ddb80643c1406d0ca10dfe6fc52009540a495e8042ea5f744f6e184667cc722483L
_b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefL
_Gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7L
_Gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fL

curve_384 = ellipticcurve.CurveFp( _p, -3, _b )
generator_384 = ellipticcurve.Point( curve_384, _Gx, _Gy, _r )

# NIST Curve P-521:
_p = 6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151L
_r = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449L
# s = 0xd09e8800291cb85396cc6717393284aaa0da64baL
# c = 0x0b48bfa5f420a34949539d2bdfc264eeeeb077688e44fbf0ad8f6d0edb37bd6b533281000518e19f1b9ffbe0fe9ed8a3c2200b8f875e523868c70c1e5bf55bad637L
_b = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00L
_Gx = 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66L
_Gy = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650L

curve_521 = ellipticcurve.CurveFp( _p, -3, _b )
generator_521 = ellipticcurve.Point( curve_521, _Gx, _Gy, _r )

  

def __main__():
  class TestFailure(Exception): pass

  def test_point_validity( generator, x, y, expected ):
    """generator defines the curve; is (x,y) a point on
       this curve? "expected" is True if the right answer is Yes."""
    if point_is_valid( generator, x, y ) == expected:
      print "Point validity tested as expected."
    else:
      raise TestFailure("*** Point validity test gave wrong result.")

  def test_signature_validity( Msg, Qx, Qy, R, S, expected ):
    """Msg = message, Qx and Qy represent the base point on
       elliptic curve c192, R and S are the signature, and
       "expected" is True iff the signature is expected to be valid."""
    pubk = Public_key( generator_192,
                       ellipticcurve.Point( curve_192, Qx, Qy ) )
    got = pubk.verifies( digest_integer( Msg ), Signature( R, S ) )
    if got == expected:
      print "Signature tested as expected: got %s, expected %s." % \
            ( got, expected )
    else:
      raise TestFailure("*** Signature test failed: got %s, expected %s." % \
                        ( got, expected ))

  print "NIST Curve P-192:"

  p192 = generator_192

  # From X9.62:

  d = 651056770906015076056810763456358567190100156695615665659L
  Q = d * p192
  if Q.x() != 0x62B12D60690CDCF330BABAB6E69763B471F994DD702D16A5L:
    raise TestFailure("*** p192 * d came out wrong.")
  else:
    print "p192 * d came out right."

  k = 6140507067065001063065065565667405560006161556565665656654L
  R = k * p192
  if R.x() != 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEADL \
     or R.y() != 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835L:
    raise TestFailure("*** k * p192 came out wrong.")
  else:
    print "k * p192 came out right."

  u1 = 2563697409189434185194736134579731015366492496392189760599L
  u2 = 6266643813348617967186477710235785849136406323338782220568L
  temp = u1 * p192 + u2 * Q
  if temp.x() != 0x885052380FF147B734C330C43D39B2C4A89F29B0F749FEADL \
     or temp.y() != 0x9CF9FA1CBEFEFB917747A3BB29C072B9289C2547884FD835L:
    raise TestFailure("*** u1 * p192 + u2 * Q came out wrong.")
  else:
    print "u1 * p192 + u2 * Q came out right."

  e = 968236873715988614170569073515315707566766479517L
  pubk = Public_key( generator_192, generator_192 * d )
  privk = Private_key( pubk, d )
  sig = privk.sign( e, k )
  r, s = sig.r, sig.s
  if r != 3342403536405981729393488334694600415596881826869351677613L \
     or s != 5735822328888155254683894997897571951568553642892029982342L:
    raise TestFailure("*** r or s came out wrong.")
  else:
    print "r and s came out right."

  valid = pubk.verifies( e, sig )
  if valid: print "Signature verified OK."
  else: raise TestFailure("*** Signature failed verification.")

  valid = pubk.verifies( e-1, sig )
  if not valid: print "Forgery was correctly rejected."
  else: raise TestFailure("*** Forgery was erroneously accepted.")

  print "Testing point validity, as per ECDSAVS.pdf B.2.2:"

  test_point_validity( \
    p192, \
    0xcd6d0f029a023e9aaca429615b8f577abee685d8257cc83aL, \
    0x00019c410987680e9fb6c0b6ecc01d9a2647c8bae27721bacdfcL, \
    False )

  test_point_validity(
    p192, \
    0x00017f2fce203639e9eaf9fb50b81fc32776b30e3b02af16c73bL, \
    0x95da95c5e72dd48e229d4748d4eee658a9a54111b23b2adbL, \
    False )

  test_point_validity(
    p192, \
    0x4f77f8bc7fccbadd5760f4938746d5f253ee2168c1cf2792L, \
    0x000147156ff824d131629739817edb197717c41aab5c2a70f0f6L, \
    False )

  test_point_validity(
    p192, \
    0xc58d61f88d905293bcd4cd0080bcb1b7f811f2ffa41979f6L, \
    0x8804dc7a7c4c7f8b5d437f5156f3312ca7d6de8a0e11867fL, \
    True )

  test_point_validity(
    p192, \
    0xcdf56c1aa3d8afc53c521adf3ffb96734a6a630a4a5b5a70L, \
    0x97c1c44a5fb229007b5ec5d25f7413d170068ffd023caa4eL, \
    True )

  test_point_validity(
    p192, \
    0x89009c0dc361c81e99280c8e91df578df88cdf4b0cdedcedL, \
    0x27be44a529b7513e727251f128b34262a0fd4d8ec82377b9L, \
    True )

  test_point_validity(
    p192, \
    0x6a223d00bd22c52833409a163e057e5b5da1def2a197dd15L, \
    0x7b482604199367f1f303f9ef627f922f97023e90eae08abfL, \
    True )
  
  test_point_validity(
    p192, \
    0x6dccbde75c0948c98dab32ea0bc59fe125cf0fb1a3798edaL, \
    0x0001171a3e0fa60cf3096f4e116b556198de430e1fbd330c8835L, \
    False )
  
  test_point_validity(
    p192, \
    0xd266b39e1f491fc4acbbbc7d098430931cfa66d55015af12L, \
    0x193782eb909e391a3148b7764e6b234aa94e48d30a16dbb2L, \
    False )
  
  test_point_validity(
    p192, \
    0x9d6ddbcd439baa0c6b80a654091680e462a7d1d3f1ffeb43L, \
    0x6ad8efc4d133ccf167c44eb4691c80abffb9f82b932b8caaL, \
    False )
  
  test_point_validity(
    p192, \
    0x146479d944e6bda87e5b35818aa666a4c998a71f4e95edbcL, \
    0xa86d6fe62bc8fbd88139693f842635f687f132255858e7f6L, \
    False )
  
  test_point_validity(
    p192, \
    0xe594d4a598046f3598243f50fd2c7bd7d380edb055802253L, \
    0x509014c0c4d6b536e3ca750ec09066af39b4c8616a53a923L, \
    False )

  print "Trying signature-verification tests from ECDSAVS.pdf B.2.4:"
  print "P-192:"
  Msg = 0x84ce72aa8699df436059f052ac51b6398d2511e49631bcb7e71f89c499b9ee425dfbc13a5f6d408471b054f2655617cbbaf7937b7c80cd8865cf02c8487d30d2b0fbd8b2c4e102e16d828374bbc47b93852f212d5043c3ea720f086178ff798cc4f63f787b9c2e419efa033e7644ea7936f54462dc21a6c4580725f7f0e7d158L
  Qx = 0xd9dbfb332aa8e5ff091e8ce535857c37c73f6250ffb2e7acL
  Qy = 0x282102e364feded3ad15ddf968f88d8321aa268dd483ebc4L
  R = 0x64dca58a20787c488d11d6dd96313f1b766f2d8efe122916L
  S = 0x1ecba28141e84ab4ecad92f56720e2cc83eb3d22dec72479L
  test_signature_validity( Msg, Qx, Qy, R, S, True )

  Msg = 0x94bb5bacd5f8ea765810024db87f4224ad71362a3c28284b2b9f39fab86db12e8beb94aae899768229be8fdb6c4f12f28912bb604703a79ccff769c1607f5a91450f30ba0460d359d9126cbd6296be6d9c4bb96c0ee74cbb44197c207f6db326ab6f5a659113a9034e54be7b041ced9dcf6458d7fb9cbfb2744d999f7dfd63f4L
  Qx = 0x3e53ef8d3112af3285c0e74842090712cd324832d4277ae7L
  Qy = 0xcc75f8952d30aec2cbb719fc6aa9934590b5d0ff5a83adb7L
  R = 0x8285261607283ba18f335026130bab31840dcfd9c3e555afL
  S = 0x356d89e1b04541afc9704a45e9c535ce4a50929e33d7e06cL
  test_signature_validity( Msg, Qx, Qy, R, S, True )

  Msg = 0xf6227a8eeb34afed1621dcc89a91d72ea212cb2f476839d9b4243c66877911b37b4ad6f4448792a7bbba76c63bdd63414b6facab7dc71c3396a73bd7ee14cdd41a659c61c99b779cecf07bc51ab391aa3252386242b9853ea7da67fd768d303f1b9b513d401565b6f1eb722dfdb96b519fe4f9bd5de67ae131e64b40e78c42ddL
  Qx = 0x16335dbe95f8e8254a4e04575d736befb258b8657f773cb7L
  Qy = 0x421b13379c59bc9dce38a1099ca79bbd06d647c7f6242336L
  R = 0x4141bd5d64ea36c5b0bd21ef28c02da216ed9d04522b1e91L
  S = 0x159a6aa852bcc579e821b7bb0994c0861fb08280c38daa09L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0x16b5f93afd0d02246f662761ed8e0dd9504681ed02a253006eb36736b563097ba39f81c8e1bce7a16c1339e345efabbc6baa3efb0612948ae51103382a8ee8bc448e3ef71e9f6f7a9676694831d7f5dd0db5446f179bcb737d4a526367a447bfe2c857521c7f40b6d7d7e01a180d92431fb0bbd29c04a0c420a57b3ed26ccd8aL
  Qx = 0xfd14cdf1607f5efb7b1793037b15bdf4baa6f7c16341ab0bL
  Qy = 0x83fa0795cc6c4795b9016dac928fd6bac32f3229a96312c4L
  R = 0x8dfdb832951e0167c5d762a473c0416c5c15bc1195667dc1L
  S = 0x1720288a2dc13fa1ec78f763f8fe2ff7354a7e6fdde44520L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0x08a2024b61b79d260e3bb43ef15659aec89e5b560199bc82cf7c65c77d39192e03b9a895d766655105edd9188242b91fbde4167f7862d4ddd61e5d4ab55196683d4f13ceb90d87aea6e07eb50a874e33086c4a7cb0273a8e1c4408f4b846bceae1ebaac1b2b2ea851a9b09de322efe34cebe601653efd6ddc876ce8c2f2072fbL
  Qx = 0x674f941dc1a1f8b763c9334d726172d527b90ca324db8828L
  Qy = 0x65adfa32e8b236cb33a3e84cf59bfb9417ae7e8ede57a7ffL
  R = 0x9508b9fdd7daf0d8126f9e2bc5a35e4c6d800b5b804d7796L
  S = 0x36f2bf6b21b987c77b53bb801b3435a577e3d493744bfab0L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0x1843aba74b0789d4ac6b0b8923848023a644a7b70afa23b1191829bbe4397ce15b629bf21a8838298653ed0c19222b95fa4f7390d1b4c844d96e645537e0aae98afb5c0ac3bd0e4c37f8daaff25556c64e98c319c52687c904c4de7240a1cc55cd9756b7edaef184e6e23b385726e9ffcba8001b8f574987c1a3fedaaa83ca6dL
  Qx = 0x10ecca1aad7220b56a62008b35170bfd5e35885c4014a19fL
  Qy = 0x04eb61984c6c12ade3bc47f3c629ece7aa0a033b9948d686L
  R = 0x82bfa4e82c0dfe9274169b86694e76ce993fd83b5c60f325L
  S = 0xa97685676c59a65dbde002fe9d613431fb183e8006d05633L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0x5a478f4084ddd1a7fea038aa9732a822106385797d02311aeef4d0264f824f698df7a48cfb6b578cf3da416bc0799425bb491be5b5ecc37995b85b03420a98f2c4dc5c31a69a379e9e322fbe706bbcaf0f77175e05cbb4fa162e0da82010a278461e3e974d137bc746d1880d6eb02aa95216014b37480d84b87f717bb13f76e1L
  Qx = 0x6636653cb5b894ca65c448277b29da3ad101c4c2300f7c04L
  Qy = 0xfdf1cbb3fc3fd6a4f890b59e554544175fa77dbdbeb656c1L
  R = 0xeac2ddecddfb79931a9c3d49c08de0645c783a24cb365e1cL
  S = 0x3549fee3cfa7e5f93bc47d92d8ba100e881a2a93c22f8d50L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0xc598774259a058fa65212ac57eaa4f52240e629ef4c310722088292d1d4af6c39b49ce06ba77e4247b20637174d0bd67c9723feb57b5ead232b47ea452d5d7a089f17c00b8b6767e434a5e16c231ba0efa718a340bf41d67ea2d295812ff1b9277daacb8bc27b50ea5e6443bcf95ef4e9f5468fe78485236313d53d1c68f6ba2L
  Qx = 0xa82bd718d01d354001148cd5f69b9ebf38ff6f21898f8aaaL
  Qy = 0xe67ceede07fc2ebfafd62462a51e4b6c6b3d5b537b7caf3eL
  R = 0x4d292486c620c3de20856e57d3bb72fcde4a73ad26376955L
  S = 0xa85289591a6081d5728825520e62ff1c64f94235c04c7f95L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0xca98ed9db081a07b7557f24ced6c7b9891269a95d2026747add9e9eb80638a961cf9c71a1b9f2c29744180bd4c3d3db60f2243c5c0b7cc8a8d40a3f9a7fc910250f2187136ee6413ffc67f1a25e1c4c204fa9635312252ac0e0481d89b6d53808f0c496ba87631803f6c572c1f61fa049737fdacce4adff757afed4f05beb658L
  Qx = 0x7d3b016b57758b160c4fca73d48df07ae3b6b30225126c2fL
  Qy = 0x4af3790d9775742bde46f8da876711be1b65244b2b39e7ecL
  R = 0x95f778f5f656511a5ab49a5d69ddd0929563c29cbc3a9e62L
  S = 0x75c87fc358c251b4c83d2dd979faad496b539f9f2ee7a289L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0x31dd9a54c8338bea06b87eca813d555ad1850fac9742ef0bbe40dad400e10288acc9c11ea7dac79eb16378ebea9490e09536099f1b993e2653cd50240014c90a9c987f64545abc6a536b9bd2435eb5e911fdfde2f13be96ea36ad38df4ae9ea387b29cced599af777338af2794820c9cce43b51d2112380a35802ab7e396c97aL
  Qx = 0x9362f28c4ef96453d8a2f849f21e881cd7566887da8beb4aL
  Qy = 0xe64d26d8d74c48a024ae85d982ee74cd16046f4ee5333905L
  R = 0xf3923476a296c88287e8de914b0b324ad5a963319a4fe73bL
  S = 0xf0baeed7624ed00d15244d8ba2aede085517dbdec8ac65f5L
  test_signature_validity( Msg, Qx, Qy, R, S, True )

  Msg = 0xb2b94e4432267c92f9fdb9dc6040c95ffa477652761290d3c7de312283f6450d89cc4aabe748554dfb6056b2d8e99c7aeaad9cdddebdee9dbc099839562d9064e68e7bb5f3a6bba0749ca9a538181fc785553a4000785d73cc207922f63e8ce1112768cb1de7b673aed83a1e4a74592f1268d8e2a4e9e63d414b5d442bd0456dL
  Qx = 0xcc6fc032a846aaac25533eb033522824f94e670fa997ecefL
  Qy = 0xe25463ef77a029eccda8b294fd63dd694e38d223d30862f1L
  R = 0x066b1d07f3a40e679b620eda7f550842a35c18b80c5ebe06L
  S = 0xa0b0fb201e8f2df65e2c4508ef303bdc90d934016f16b2dcL
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0x4366fcadf10d30d086911de30143da6f579527036937007b337f7282460eae5678b15cccda853193ea5fc4bc0a6b9d7a31128f27e1214988592827520b214eed5052f7775b750b0c6b15f145453ba3fee24a085d65287e10509eb5d5f602c440341376b95c24e5c4727d4b859bfe1483d20538acdd92c7997fa9c614f0f839d7L
  Qx = 0x955c908fe900a996f7e2089bee2f6376830f76a19135e753L
  Qy = 0xba0c42a91d3847de4a592a46dc3fdaf45a7cc709b90de520L
  R = 0x1f58ad77fc04c782815a1405b0925e72095d906cbf52a668L
  S = 0xf2e93758b3af75edf784f05a6761c9b9a6043c66b845b599L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0x543f8af57d750e33aa8565e0cae92bfa7a1ff78833093421c2942cadf9986670a5ff3244c02a8225e790fbf30ea84c74720abf99cfd10d02d34377c3d3b41269bea763384f372bb786b5846f58932defa68023136cd571863b304886e95e52e7877f445b9364b3f06f3c28da12707673fecb4b8071de06b6e0a3c87da160cef3L
  Qx = 0x31f7fa05576d78a949b24812d4383107a9a45bb5fccdd835L
  Qy = 0x8dc0eb65994a90f02b5e19bd18b32d61150746c09107e76bL
  R = 0xbe26d59e4e883dde7c286614a767b31e49ad88789d3a78ffL
  S = 0x8762ca831c1ce42df77893c9b03119428e7a9b819b619068L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0xd2e8454143ce281e609a9d748014dcebb9d0bc53adb02443a6aac2ffe6cb009f387c346ecb051791404f79e902ee333ad65e5c8cb38dc0d1d39a8dc90add5023572720e5b94b190d43dd0d7873397504c0c7aef2727e628eb6a74411f2e400c65670716cb4a815dc91cbbfeb7cfe8c929e93184c938af2c078584da045e8f8d1L
  Qx = 0x66aa8edbbdb5cf8e28ceb51b5bda891cae2df84819fe25c0L
  Qy = 0x0c6bc2f69030a7ce58d4a00e3b3349844784a13b8936f8daL
  R = 0xa4661e69b1734f4a71b788410a464b71e7ffe42334484f23L
  S = 0x738421cf5e049159d69c57a915143e226cac8355e149afe9L
  test_signature_validity( Msg, Qx, Qy, R, S, False )

  Msg = 0x6660717144040f3e2f95a4e25b08a7079c702a8b29babad5a19a87654bc5c5afa261512a11b998a4fb36b5d8fe8bd942792ff0324b108120de86d63f65855e5461184fc96a0a8ffd2ce6d5dfb0230cbbdd98f8543e361b3205f5da3d500fdc8bac6db377d75ebef3cb8f4d1ff738071ad0938917889250b41dd1d98896ca06fbL
  Qx = 0xbcfacf45139b6f5f690a4c35a5fffa498794136a2353fc77L
  Qy = 0x6f4a6c906316a6afc6d98fe1f0399d056f128fe0270b0f22L
  R = 0x9db679a3dafe48f7ccad122933acfe9da0970b71c94c21c1L
  S = 0x984c2db99827576c0a41a5da41e07d8cc768bc82f18c9da9L
  test_signature_validity( Msg, Qx, Qy, R, S, False )



  print "Testing the example code:"

  # Building a public/private key pair from the NIST Curve P-192:

  g = generator_192
  n = g.order()

  # (random.SystemRandom is supposed to provide
  # crypto-quality random numbers, but as Debian recently
  # illustrated, a systems programmer can accidentally
  # demolish this security, so in serious applications
  # further precautions are appropriate.)

  randrange = random.SystemRandom().randrange
  
  secret = randrange( 1, n )
  pubkey = Public_key( g, g * secret )
  privkey = Private_key( pubkey, secret )

  # Signing a hash value:
  
  hash = randrange( 1, n )
  signature = privkey.sign( hash, randrange( 1, n ) )

  # Verifying a signature for a hash value:
  
  if pubkey.verifies( hash, signature ):
    print "Demo verification succeeded."
  else:
    raise TestFailure("*** Demo verification failed.")

  if pubkey.verifies( hash-1, signature ):
    raise TestFailure( "**** Demo verification failed to reject tampered hash.")
  else:
    print "Demo verification correctly rejected tampered hash."

if __name__ == "__main__":
  __main__()
