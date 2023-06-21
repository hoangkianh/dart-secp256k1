// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'dart:math' as math;
import 'package:convert/convert.dart' as convert;

import 'package:dart_bignumber/dart_bignumber.dart';

import 'main.dart';

class AffinePoint {
  final BigNumber x;
  final BigNumber y;

  AffinePoint(this.x, this.y);
} // Point in 2d xy affine coordinates

class Point {
  final String _hex = '';
  final BigNumber px;
  final BigNumber py;
  final BigNumber pz;
  static final BASE = Point(Gx, Gy, BigNumber.ONE); // Generator / base point
  static final ZERO = Point(BigNumber.ZERO, BigNumber.ONE, BigNumber.ZERO); // Identity / zero point

  Point(this.px, this.py, this.pz); // 3d less function

  get x {
    return aff().x;
  } // .x, .y will call expensive toAffine:

  get y {
    return aff().y;
  }

  bool equals(Point other) {
    // Equality check: compare points
    var X1 = px;
    var Y1 = py;
    var Z1 = pz;

    var X2 = other.px;
    var Y2 = other.py;
    var Z2 = other.pz;

    var X1Z2 = mod(X1 * Z2);
    var X2Z1 = mod(X2 * Z1);
    var Y1Z2 = mod(Y1 * Z2);
    var Y2Z1 = mod(Y2 * Z1);
    return X1Z2 == X2Z1 && Y1Z2 == Y2Z1;
  }

  negate() {
    return Point(px, mod(-py), pz);
  } // Flip point over y coord

  double() {
    return add(this);
  } // Point doubling: P+P, complete formula.

  dynamic add(Point other) {
    var X1 = px, Y1 = py, Z1 = pz;
    var X2 = other.px, Y2 = other.py, Z2 = other.pz;

    var a = CURVE['a'], b = CURVE['b']; // Cost: 12M + 0S + 3*a + 3*b3 + 23add

    if (a == null || b == null) throw Exception('invalid a, b');
    var X3 = BigNumber.ZERO, Y3 = BigNumber.ZERO, Z3 = BigNumber.ZERO;
    var b3 = mod(b * BigNumber.from(3));
    var t0 = mod(X1 * X2), t1 = mod(Y1 * Y2), t2 = mod(Z1 * Z2), t3 = mod(X1 + Y1); // step 1
    var t4 = mod(X2 + Y2); // step 5
    t3 = mod(t3 * t4);
    t4 = mod(t0 + t1);
    t3 = mod(t3 - t4);
    t4 = mod(X1 + Z1);
    var t5 = mod(X2 + Z2); // step 10
    t4 = mod(t4 * t5);
    t5 = mod(t0 + t2);
    t4 = mod(t4 - t5);
    t5 = mod(Y1 + Z1);
    X3 = mod(Y2 + Z2); // step 15
    t5 = mod(t5 * X3);
    X3 = mod(t1 + t2);
    t5 = mod(t5 - X3);
    Z3 = mod(a * t4);
    X3 = mod(b3 * t2); // step 20
    Z3 = mod(X3 + Z3);
    X3 = mod(t1 - Z3);
    Z3 = mod(t1 + Z3);
    Y3 = mod(X3 * Z3);
    t1 = mod(t0 + t0); // step 25
    t1 = mod(t1 + t0);
    t2 = mod(a * t2);
    t4 = mod(b3 * t4);
    t1 = mod(t1 + t2);
    t2 = mod(t0 - t2); // step 30
    t2 = mod(a * t2);
    t4 = mod(t4 + t2);
    t0 = mod(t1 * t4);
    Y3 = mod(Y3 + t0);
    t0 = mod(t5 * t4); // step 35
    X3 = mod(t3 * X3);
    X3 = mod(X3 - t0);
    t0 = mod(t3 * t1);
    Z3 = mod(t5 * Z3);
    Z3 = mod(Z3 + t0); // step 40
    return Point(X3, Y3, Z3);
  }

  Point mul(BigNumber n, [bool safe = true]) {
    if (!safe && n.isZero()) {
      return ZERO; // in unsafe mode, allow zero
    }
    if (!ge(n)) {
      err('invalid scalar'); // must be 0 < n < CURVE.n
    }
    if (equals(BASE)) {
      return wNAF(n)['p'] ?? ZERO; // use precomputes for base point
    }
    var p = I, f = G; // init result point & fake point
    for (var d = this; n > BigNumber.ZERO; d = d.double(), n = n.shr(1)) {
      // double-and-add ladder
      if (n & BigNumber.ONE > BigNumber.ZERO) {
        p = p.add(d); // if bit is present, add to point
      } else if (safe) {
        f = f.add(d); // if not, add to fake for timing safety
      }
    }
    return p;
  }

  Point mulAddQUns(Point R, BigNumber u1, BigNumber u2) {
    // Double scalar mult. Q = u1⋅G + u2⋅R.
    return mul(u1, false).add(R.mul(u2, false)).ok(); // Unsafe: do NOT use for stuff related
  }

  static Point fromAffine(AffinePoint p) => Point(p.x, p.y, BigNumber.ONE);

  static Point fromHex(String hex) {
    // Convert Uint8List or hex string to Point
    Uint8List hexBytes = Uint8List.fromList(convert.hex.decode(hex)); // convert hex string to Uint8Array
    Point p = ZERO;
    int head = hexBytes[0];
    Uint8List tail = hexBytes.sublist(1); // first byte is prefix, rest is data
    BigNumber x = slcNum(tail, 0, fLen);
    int len = hexBytes.length; // next 32 bytes are x coordinate

    if (len == 33 && [0x02, 0x03].contains(head)) {
      // compressed points: 33b, start
      if (!fe(x)) {
        err('Point hex invalid: x not FE');
      } // with byte 0x02 or 0x03. Check if 0<x<P
      var y = sqrt(crv(x)); // x³ + ax + b is right side of equation
      var isYOdd = (y & (BigNumber.ONE)) == BigNumber.ONE; // y² is equivalent left-side. Calculate y²:
      var headOdd = (head & 1) == 1; // y = √y²; there are two solutions: y, -y
      if (headOdd != isYOdd) {
        y = mod(-y);
      } // determine proper solution
      p = Point(x, y, BigNumber.ONE); // create point
    } // Uncompressed points: 65b, start with 0x04
    if (len == 65 && head == 0x04) {
      p = Point(x, slcNum(tail, fLen, 2 * fLen), BigNumber.ONE);
    }
    // Verify the result
    if (p.equals(ZERO)) {
      err('Point is not on curve');
    }
    return p.ok();
  }

  static fromPrivateKey(String pk) {
    if (!pk.startsWith('0x')) {
      pk = '0x$pk';
    }
    return BASE.mul(toPriv(BigNumber.from(pk)));
  } // Create point from a private key.

  AffinePoint toAffine() {
    // Convert point to 2d xy affine point.
    if (equals(ZERO)) {
      // fast-path for zero point
      return AffinePoint(BigNumber.ZERO, BigNumber.ZERO);
    }
    if (pz == BigNumber.ONE) {
      // if z is 1, pass affine coordinates as-is
      return AffinePoint(px, py);
    }
    var iz = inv(pz); // z^-1: invert z
    if (mod(pz * iz) != BigNumber.ONE) {
      // (z * z^-1) must be 1, otherwise bad math
      err('invalid inverse');
    }
    return AffinePoint(mod(px * iz), mod(py * iz)); // x = x*z^-1; y = y*z^-1
  }

  Point assertValidity() {
    // Checks if the point is valid and on-curve
    var affPoint = aff(); // convert to 2d xy affine point.
    if (!fe(affPoint.x) || !fe(affPoint.y)) {
      err('Point invalid: x or y');
    } // x and y must be in range 0 < n < P

    // y² = x³ + ax + b, must be equal
    if (mod(affPoint.y.mul(affPoint.y)) != crv(affPoint.x)) {
      err('Point invalid: not on curve');
    }
    return this;
  }

  // Aliases to compress code
  Point multiply(BigNumber n) {
    return mul(n);
  }

  Point ok() {
    return assertValidity();
  }

  AffinePoint aff() {
    return toAffine();
  }

  String toHex([bool isCompressed = true]) {
    // Encode point to hex string.
    var affPoint = aff(); // convert to 2d xy affine point
    String head = isCompressed ? ((affPoint.y & BigNumber.ONE).isZero() ? '02' : '03') : '04'; // 0x02, 0x03, 0x04 prefix

    String xHex = n2h(affPoint.x);
    String yHex = n2h(affPoint.y);
    var result = '$head$xHex${isCompressed ? '' : yHex}';
    return result;
  }

  Uint8List toRawBytes([bool isCompressed = true]) {
    String hex = toHex(isCompressed);
    return Uint8List.fromList(convert.hex.decode(hex));
  }

  @override
  int get hashCode => _hex.hashCode;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;

    if (other.runtimeType != runtimeType) return false;

    return equals(other as Point);
  }

  @override
  String toString() {
    return 'Point {\n  px: $px,\n  py: $py,\n  pz: $pz\n}';
  }
}

Point G = Point.BASE; // Generator, identity points
Point I = Point.ZERO; // Generator, identity points
const W = 8; // Precomputes-related code. W = window size

List<Point> precompute() {
  // They give 12x faster getPublicKey(),
  List<Point> points = List.empty(growable: true); // 10x sign(), 2x verify(). To achieve this,
  const windows = 256 / W + 1; // app needs to spend 40ms+ to calculate
  Point p = G, b = p; // a lot of points related to base point G.
  for (var w = 0; w < windows; w++) {
    // Points are stored in array and used
    b = p; // any time Gx multiplication is done.
    points.add(b); // They consume 16-32 MiB of RAM.
    for (var i = 1; i < math.pow(2, W - 1); i++) {
      b = b.add(p);
      points.add(b);
    }
    p = b.double(); // Precomputes don't speed-up getSharedKey,
  } // which multiplies user point by scalar,
  return points; // when precomputes are using base point
}

List<Point> Gpows = List.empty(growable: true);
neg(bool cnd, Point p) {
  var n = p.negate();
  return cnd ? n : p;
} // negate

Map<String, Point> wNAF(BigNumber n) {
  // w-ary non-adjacent form (wNAF) method.
  // Compared to other point mult methods,
  if (Gpows.isEmpty) {
    Gpows = precompute();
  }
  var comp = Gpows; // stores 2x less points using subtraction
  Point p = I, f = G; // f must be G, or could become I in the end
  const windows = 1 + 256 / W; // W=8 17 windows
  var wsize = math.pow(2, W - 1); // W=8 128 window size
  var mask = BigNumber.from(math.pow(2, W) - 1); // W=8 will create mask 0b11111111
  var maxNum = math.pow(2, W); // W=8 256
  var shiftBy = BigNumber.from(W); // W=8 8
  for (var w = 0; w < windows; w++) {
    var off = w * wsize;
    var wbits = (n & mask); // extract W bits.
    n >>= int.parse(shiftBy.toString()); // shift number by W bits.
    if (wbits.toNumber() > wsize) {
      wbits -= BigNumber.from(maxNum);
      n += BigNumber.ONE;
    } // split if bits > max: +224 => 256-32
    var off1 = int.parse(off.toString());
    var off2 = int.parse((off + wbits.abs().toNumber() - 1).toString()); // offsets, evaluate both
    var cnd1 = w % 2 != 0, cnd2 = wbits.isNegative(); // conditions, evaluate both
    if (wbits.isZero()) {
      f = f.add(neg(cnd1, comp[off1])); // bits are 0: add garbage to fake point
    } else {
      //          ^ can't add off2, off2 = I
      p = p.add(neg(cnd2, comp[off2])); // bits are 1: add to result point
    }
  }
  return {'p': p, 'f': f}; // return both real and fake points for JIT
} // !! you can disable precomputes by commenting-out call of the wNAF() inside Point#mul()

String getPublicKey(String privKey, [bool isCompressed = true]) {
  if (privKey.length < 2 * fLen) {
    privKey = padh(BigNumber.from(privKey), 2 * fLen);
  }
  // Make public key from priv
  Point point = Point.fromPrivateKey(privKey);
  var bytes = point.toRawBytes(isCompressed);
  var result = convert.hex.encode(bytes); // 33b or 65b output
  return result;
}
