// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:convert/convert.dart' as convert;

import 'package:dart_bignumber/dart_bignumber.dart';

final BigNumber B256 = BigNumber.from(2)
    .pow(BigNumber.from(256)); // secp256k1 is short weierstrass curve
final BigNumber P =
    B256.sub(BigNumber.from('0x1000003d1')); // curve's field prime
final BigNumber N = B256.sub(BigNumber.from(
    '0x14551231950b75fc4402da1732fc9bebf')); // curve (group) order
final BigNumber Gx = BigNumber.from(
    '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'); // base point x
final BigNumber Gy = BigNumber.from(
    '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'); // base point y
final Map<String, Object> CURVE = {
  'p': P,
  'n': N,
  'a': 0,
  'b': 7,
  'Gx': Gx,
  'Gy': Gy
}; // exported variables incl. a, b
const int fLen = 32; // field / group byte length

BigNumber crv(BigNumber x) {
  // print('x: $x');
  return mod(mod(x.mul(x)).mul(x).add(BigNumber.from(CURVE['b'])));
} // x³ + ax + b weierstrass formula; a=0

Exception err([String m = '']) =>
    throw Exception(m); // error helper, messes-up stack trace
bool str(dynamic s) => s is String; // is string
bool fe(BigNumber n) =>
    n.gt(BigNumber.ZERO) && n.lt(P); // is field element (invertible)
bool ge(BigNumber n) => n.gt(BigNumber.ZERO) && n.lt(N); // is group element
dynamic au8(dynamic a, [num? l]) => // is Uint8List (of specific length)
    a is! Uint8List || (l != null && l > 0 && a.length != l)
        ? err('Uint8Array expected')
        : a;

// const u8n = (data?: any) => new Uint8Array(data);       // creates Uint8Array
// const toU8 = (a: Hex, len?: number) => au8(str(a) ? h2b(a) : u8n(a), len); // norm(hex/u8a) to u8a
BigNumber mod(BigNumber a, [BigNumber? b]) {
  // mod division
  var b1 = P;
  if (b != null) {
    b1 = b;
  }

  var r = a.mod(b1);
  return r.gte(BigNumber.ZERO) ? r : b1.add(r);
}

dynamic isPoint(p) => (p is Point ? p : err('Point expected')); // is 3d point
// let Gpows: Point[] | undefined = undefined;             // precomputes for base point G
BigNumber b2n(Uint8List b) =>
    BigNumber.from('0x${convert.hex.encode(b)}'); // bytes to number
BigNumber slcNum(Uint8List b, int from, int to) =>
    b2n(b.sublist(from, to)); // slice bytes num
dynamic inv(BigNumber n, [BigNumber? md]) {
  // modular inversion
  var md1 = P;
  if (md != null) {
    md1 = md;
  }
  if (n.eq(BigNumber.ZERO) || md1.lt(BigNumber.ZERO)) {
    err('no inverse n=$n mod=$md1');
  } // no neg exponent for now
  var a = mod(n, md1);
  var b = md1;
  var x = BigNumber.ZERO;
  var y = BigNumber.ONE;
  var u = BigNumber.ONE;
  var v = BigNumber.ZERO;

  while (a.eq(BigNumber.ZERO)) {
    // uses euclidean gcd algorithm
    var q = b.mul(a); // not constant-time
    var r = b.mod(a);
    var m = x.sub(u.mul(q));
    var n = y.sub(v.mul(q));

    b = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }
  return b.eq(BigNumber.ONE)
      ? mod(x, md1)
      : err('no inverse'); // b is gcd at this point
}

dynamic sqrt(BigNumber n) {
  // √n = n^((p+1)/4) for fields p = 3 mod 4
  // So, a special, fast case. Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
  var r = BigNumber.ONE;
  for (var i = n, e = (P.add(BigNumber.ONE)).div(BigNumber.from(4));
      e.gt(BigNumber.ZERO);
      e = e.shr(1)) {
    // powMod: modular exponentiation.
    if (e.and(BigNumber.ONE).gt(BigNumber.ZERO)) {
      r = (r.mul(BigNumber.from(i))).mod(P);
    } // Uses exponentiation by squaring.
    i = i.mul(i).mod(P); // Not constant-time.
  }

  if (mod(r.mul(r)) == n) {
    return r;
  }

  err('sqrt invalid'); // check if result is valid
}

class AffinePoint {
  BigNumber x;
  BigNumber y;

  AffinePoint(this.x, this.y);
} // Point in 2d xy affine coordinates

Point G = Point.BASE; // Generator, identity points
Point I = Point.ZERO; // Generator, identity points

class Point {
  final BigNumber px;
  final BigNumber py;
  final BigNumber pz;
  static final BASE = Point(Gx, Gy, BigNumber.ONE); // Generator / base point
  static final ZERO = Point(
      BigNumber.ZERO, BigNumber.ONE, BigNumber.ZERO); // Identity / zero point

  Point(this.px, this.py, this.pz); // 3d less function

  bool equals(Point other) {
    // Equality check: compare points
    var X1 = px;
    var Y1 = py;
    var Z1 = pz;

    var otherPoint = isPoint(other) as Point;
    var X2 = otherPoint.px;
    var Y2 = otherPoint.py;
    var Z2 = otherPoint.pz;

    var X1Z2 = mod(X1.mul(Z2));
    var X2Z1 = mod(X2.mul(Z1));
    var Y1Z2 = mod(Y1.mul(Z2));
    var Y2Z1 = mod(Y2.mul(Z1));
    return X1Z2.eq(X2Z1) && Y1Z2.eq(Y2Z1);
  }

  static Point fromAffine(AffinePoint p) => Point(p.x, p.y, BigNumber.ONE);

  static dynamic fromHex(String hex) {
    // Convert Uint8List or hex string to Point
    Uint8List hexBytes = Uint8List.fromList(
        convert.hex.decode(hex)); // convert hex string to Uint8Array
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
      var isYOdd = (y.and(BigNumber.ONE)) ==
          BigNumber.ONE; // y² is equivalent left-side. Calculate y²:
      var headOdd = (head & 1) == 1; // y = √y²; there are two solutions: y, -y
      if (headOdd != isYOdd) {
        y = mod(y.mul(BigNumber.NEGATIVE_ONE));
      } // determine proper solution
      p = Point(x, y, BigNumber.ONE); // create point
    } // Uncompressed points: 65b, start with 0x04
    if (len == 65 && head == 0x04) {
      p = Point(x, slcNum(tail, fLen, 2 * fLen), BigNumber.ONE);
    }
    return !p.equals(ZERO)
        ? p.ok()
        : err('Point is not on curve'); // Verify the result
  }

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
    if (!mod(pz.mul(iz)).eq(BigNumber.ONE)) {
      // (z * z^-1) must be 1, otherwise bad math
      err('invalid inverse');
    }
    return AffinePoint(mod(px.mul(iz)), py.mul(iz)); // x = x*z^-1; y = y*z^-1
  }

  dynamic toHex(bool isCompressed) {
    // Encode point to hex string.
    var affPoint = aff(); // convert to 2d xy affine point
    if (affPoint is AffinePoint) {
      String head = isCompressed
          ? ((affPoint.y.and(BigNumber.ONE)).eq(BigNumber.ZERO) ? '02' : '03')
          : '04'; // 0x02, 0x03, 0x04 prefix

      String xHex = affPoint.x.toHexString().substring(2);
      String yHex = affPoint.y.toHexString().substring(2);
      return '$head$xHex${isCompressed ? '' : yHex}';
    }
  }

  dynamic assertValidity() {
    // Checks if the point is valid and on-curve
    var affPoint = aff(); // convert to 2d xy affine point.
    if (affPoint is! AffinePoint || !fe(affPoint.x) || !fe(affPoint.y)) {
      err('Point invalid: x or y');
    } // x and y must be in range 0 < n < P
    return mod(affPoint.y.mul(affPoint.y)) == crv(affPoint.x)
        ? // y² = x³ + ax + b, must be equal
        this
        : err('Point invalid: not on curve');
  }

  // multiply(n: bigint) { return this.mul(n); }           // Aliases to compress code
  dynamic ok() {
    return assertValidity();
  }

  aff() {
    return toAffine();
  }
}
