// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import "dart:math" as math;
import 'package:convert/convert.dart' as convert;

import 'package:dart_bignumber/dart_bignumber.dart';

final BigNumber B256 = BigNumber.from(2)
    .pow(BigNumber.from(256)); // secp256k1 is short weierstrass curve
final BigNumber P =
    B256 - (BigNumber.from('0x1000003d1')); // curve's field prime
final BigNumber N = B256 -
    (BigNumber.from(
        '0x14551231950b75fc4402da1732fc9bebf')); // curve (group) order
final BigNumber Gx = BigNumber.from(
    '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'); // base point x
final BigNumber Gy = BigNumber.from(
    '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'); // base point y
final Map<String, BigNumber> CURVE = {
  'p': P,
  'n': N,
  'a': BigNumber.from(0),
  'b': BigNumber.from(7),
  'Gx': Gx,
  'Gy': Gy
}; // exported variables incl. a, b
const int fLen = 32; // field / group byte length

BigNumber crv(BigNumber x) {
  // print('x: $x');
  return mod(mod(x * x) * x + BigNumber.from(CURVE['b']));
} // x³ + ax + b weierstrass formula; a=0

Exception err([String m = '']) =>
    throw Exception(m); // error helper, messes-up stack trace
bool str(dynamic s) => s is String; // is string
bool fe(BigNumber n) =>
    n > BigNumber.ZERO && n < P; // is field element (invertible)
bool ge(BigNumber n) => n < BigNumber.ZERO && n < N; // is group element
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

  var r = a % b1;
  return r >= BigNumber.ZERO ? r : b1 + r;
}

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
  for (var i = n, e = (P + BigNumber.ONE) / BigNumber.from(4);
      e > BigNumber.ZERO;
      e >>= 1) {
    // powMod: modular exponentiation.
    if (e & BigNumber.ONE > BigNumber.ZERO) {
      r = (r * BigNumber.from(i)) % P;
    } // Uses exponentiation by squaring.
    i = (i * i) % P; // Not constant-time.
  }

  if (mod(r * r) == n) {
    return r;
  }

  err('sqrt invalid'); // check if result is valid
}

dynamic toPriv(BigNumber p) {
  return ge(p)
      ? p
      : err('private key out of range'); // check if bigint is in range
}

// const W = 8;                                            // Precomputes-related code. W = window size
// List<Point> precompute() {                              // They give 12x faster getPublicKey(),
//   List<Point> points = List.empty(growable: true);                           // 10x sign(), 2x verify(). To achieve this,
//   const windows = 256 / W + 1;                          // app needs to spend 40ms+ to calculate
//   var p = G, b = p;                                     // a lot of points related to base point G.
//   for (var w = 0; w < windows; w++) {                   // Points are stored in array and used
//     b = p;                                              // any time Gx multiplication is done.
//     points.add(b);                                     // They consume 16-32 MiB of RAM.
//     for (var i = 1; i < math.pow(2, W - 1); i++) { b = b.add(p); points.add(b); }
//     p = b.double();                                     // Precomputes don't speed-up getSharedKey,
//   }                                                     // which multiplies user point by scalar,
//   return points;                                        // when precomputes are using base point
// }
// Map<String, Point> wNAF(BigNumber n) {   // w-ary non-adjacent form (wNAF) method.
//                                                         // Compared to other point mult methods,
//   const comp = Gpows || (Gpows = precompute());         // stores 2x less points using subtraction
//   const neg = (cnd: boolean, p: Point) => { let n = p.negate(); return cnd ? n : p; } // negate
//   let p = I, f = G;                                     // f must be G, or could become I in the end
//   const windows = 1 + 256 / W;                          // W=8 17 windows
//   const wsize = 2 ** (W - 1);                           // W=8 128 window size
//   const mask = BigInt(2 ** W - 1);                      // W=8 will create mask 0b11111111
//   const maxNum = 2 ** W;                                // W=8 256
//   const shiftBy = BigInt(W);                            // W=8 8
//   for (let w = 0; w < windows; w++) {
//     const off = w * wsize;
//     let wbits = Number(n & mask);                       // extract W bits.
//     n >>= shiftBy;                                      // shift number by W bits.
//     if (wbits > wsize) { wbits -= maxNum; n += 1n; }    // split if bits > max: +224 => 256-32
//     const off1 = off, off2 = off + Math.abs(wbits) - 1; // offsets, evaluate both
//     const cnd1 = w % 2 !== 0, cnd2 = wbits < 0;         // conditions, evaluate both
//     if (wbits === 0) {
//       f = f.add(neg(cnd1, comp[off1]));                 // bits are 0: add garbage to fake point
//     } else {                                            //          ^ can't add off2, off2 = I
//       p = p.add(neg(cnd2, comp[off2]));                 // bits are 1: add to result point
//     }
//   }
//   return { p, f }                                       // return both real and fake points for JIT
// };        // !! you can disable precomputes by commenting-out call of the wNAF() inside Point#mul()

class AffinePoint {
  BigNumber x;
  BigNumber y;

  AffinePoint(this.x, this.y);
} // Point in 2d xy affine coordinates

Point G = Point.BASE; // Generator, identity points
Point I = Point.ZERO; // Generator, identity points

class Point {
  final String _hex = '';
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

    var X2 = other.px;
    var Y2 = other.py;
    var Z2 = other.pz;

    var X1Z2 = mod(X1 * Z2);
    var X2Z1 = mod(X2 * Z1);
    var Y1Z2 = mod(Y1 * Z2);
    var Y2Z1 = mod(Y2 * Z1);
    return X1Z2 == X2Z1 && Y1Z2 == Y2Z1;
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;

    if (other.runtimeType != runtimeType) return false;

    return equals(other as Point);
  }

  @override
  int get hashCode => _hex.hashCode;

// negate() { return new Point(this.px, mod(-this.py), this.pz); } // Flip point over y coord
//     double() { return this.add(this); } // Point doubling: P+P, complete formula.
  add(Point other) {
    var X1 = px, Y1 = py, Z1 = px;
    var X2 = other.px, Y2 = other.py, Z2 = other.pz;

    var a = CURVE['a'], b = CURVE['b']; // Cost: 12M + 0S + 3*a + 3*b3 + 23add

    if (a == null || b == null) throw Exception('invalid a, b');
    var X3 = BigNumber.ZERO, Y3 = BigNumber.ZERO, Z3 = BigNumber.ZERO;
    var b3 = mod(b * (BigNumber.from(3)));
    var t0 = mod(X1 * (X2)),
        t1 = mod(Y1 * (Y2)),
        t2 = mod(Z1 * (Z2)),
        t3 = mod(X1 * (Y1)); // step 1
    var t4 = mod(X2 + (Y2)); // step 5
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
  // mul(BigNumber n, [bool? safe = true]) {
  //   if ((safe == null || !safe) && n.eq(BigNumber.ZERO)) {
  //     return ZERO; // in unsafe mode, allow zero
  //   }
  //   if (!ge(n)) {
  //     err('invalid scalar'); // must be 0 < n < CURVE.n
  //   }
  //   if (equals(BASE)) {
  //     return wNAF(n).p; // use precomputes for base point
  //   }
  //   var p = I, f = G; // init result point & fake point
  //   for (var d = this; n.gt(BigNumber.ZERO); d = d.double(), n = n.shr(1)) {
  //     // double-and-add ladder
  //     if (n.and(BigNumber.ONE).gt(BigNumber.ZERO)) {
  //       p = p.add(d); // if bit is present, add to point
  //     } else if (safe) {
  //       f = f.add(d); // if not, add to fake for timing safety
  //     }
  //   }
  //   return p;
  // }

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
      var isYOdd = (y & (BigNumber.ONE)) ==
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

  // static fromPrivateKey(k) {
  //   return BASE.mul(toPriv(k));
  // } // Create point from a private key.

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
