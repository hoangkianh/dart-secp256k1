// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:convert/convert.dart' as convert;

import 'package:dart_bignumber/dart_bignumber.dart';

final BigNumber B256 = BigNumber.from(2).pow(BigNumber.from(256)); // secp256k1 is short weierstrass curve
final BigNumber P = B256 - (BigNumber.from('0x1000003d1')); // curve's field prime
final BigNumber N = B256 - (BigNumber.from('0x14551231950b75fc4402da1732fc9bebf')); // curve (group) order
final BigNumber Gx = BigNumber.from('0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'); // base point x
final BigNumber Gy = BigNumber.from('0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'); // base point y
final Map<String, BigNumber> CURVE = {'p': P, 'n': N, 'a': BigNumber.from(0), 'b': BigNumber.from(7), 'Gx': Gx, 'Gy': Gy}; // exported variables incl. a, b
const int fLen = 32; // field / group byte length

BigNumber crv(BigNumber x) {
  return mod(mod(x * x) * x + BigNumber.from(CURVE['b'])); // x³ + ax + b weierstrass formula; a=0
}

Exception err([String m = '']) => throw Exception(m); // error helper, messes-up stack trace
bool str(dynamic s) => s is String; // is string
bool fe(BigNumber n) => n > BigNumber.ZERO && n < P; // is field element (invertible)
bool ge(BigNumber n) => n > BigNumber.ZERO && n < N; // is group element
BigNumber mod(BigNumber a, [BigNumber? b]) {
  // mod division
  var b1 = P;
  if (b != null) {
    b1 = b;
  }

  var r = a % b1;
  return r >= BigNumber.ZERO ? r : b1 + r;
}

String padh(BigNumber n, int pad) => n.toHexString().substring(2).padLeft(pad, '0');
BigNumber b2n(Uint8List b) => BigNumber.from('0x${convert.hex.encode(b)}'); // bytes to number
BigNumber slcNum(Uint8List b, int from, int to) => b2n(b.sublist(from, to)); // slice bytes num
List<int> n2b(BigNumber n) {
  if (n < BigNumber.ZERO || n >= B256) {
    err('bignumber out of range');
  }

  return convert.hex.decode(padh(n, 2 * fLen));
}

String n2h(BigNumber n) => convert.hex.encode(n2b(n));
BigNumber inv(BigNumber n, [BigNumber? md]) {
  // modular inversion
  var md1 = P;
  if (md != null) {
    md1 = md;
  }
  if (n.isZero() || md1 <= BigNumber.ZERO) {
    err('no inverse n=$n mod=$md1');
  } // no neg exponent for now
  var a = mod(n, md1);
  var b = md1;
  var x = BigNumber.ZERO;
  var y = BigNumber.ONE;
  var u = BigNumber.ONE;
  var v = BigNumber.ZERO;

  while (!a.isZero()) {
    // uses euclidean gcd algorithm
    var q = b / a, r = b % a; // not constant-time
    var m = x - u * q;
    var n = y - v * q;

    b = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }

  if (b != BigNumber.ONE) {
    err('no inverse');
  }
  return mod(x, md1); // b is gcd at this point
}

BigNumber sqrt(BigNumber n) {
  // √n = n^((p+1)/4) for fields p = 3 mod 4
  // So, a special, fast case. Paper: "Square Roots from 1;24,51,10 to Dan Shanks".
  var r = BigNumber.ONE;
  for (var i = n, e = (P + BigNumber.ONE) / BigNumber.from(4); e > BigNumber.ZERO; e >>= 1) {
    // powMod: modular exponentiation.
    if (e & BigNumber.ONE > BigNumber.ZERO) {
      r = (r * BigNumber.from(i)) % P;
    } // Uses exponentiation by squaring.
    i = (i * i) % P; // Not constant-time.
  }

  if (mod(r * r) != n) {
    err('sqrt invalid'); // check if result is valid
  }
  return r;
}

BigNumber toPriv(BigNumber p) {
  if (!ge(p)) {
    err('private key out of range');
  }
  return p; // check if bigint is in range
}
Uint8List hashToPrivateKey(String hash) {           // FIPS 186 B.4.1 compliant key generation
  const minLen = fLen + 8;                              // being neglible.
  if (hash.length < minLen || hash.length > 1024) err('expected proper params');
  BigNumber n = mod(b2n(Uint8List.fromList(hash.codeUnits)), N - BigNumber.ONE) + BigNumber.ONE;              // takes at least n+8 bytes
  return Uint8List.fromList(convert.hex.decode(n.toHexString()));
}
