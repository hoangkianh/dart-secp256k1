// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:convert/convert.dart' as convert;
import 'package:dart_bignumber/dart_bignumber.dart';

import 'main.dart';
import 'point.dart';

bool moreThanHalfN(BigNumber n) => n > (N >> 1); // if a number is bigger than CURVE.n/2

BigNumber bits2int(Uint8List bytes) {
  // RFC6979: ensure ECDSA msg is X bytes.
  var delta = bytes.length * 8 - 256; // RFC suggests optional truncating via bits2octets
  var num = b2n(bytes); // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which
  return delta > 0 ? num >> delta : num; // matches bits2int. bits2int can produce res>N.
}

BigNumber bits2int_modN(Uint8List bytes) {
  // int2octets can't be used; pads small msgs
  return mod(bits2int(bytes), N); // with 0: BAD for trunc as per RFC vectors
}

class Signature {
  final String _hex = '';
  final BigNumber r;
  final BigNumber s;
  final int? recover;

  Signature(this.r, this.s, [this.recover]) {
    assertValidity();
  }

  static fromCompact(String hex) {
    // create signature from 64b compact repr
    var bytes = Uint8List.fromList(convert.hex.decode(hex));
    return Signature(slcNum(bytes, 0, fLen), slcNum(bytes, fLen, 2 * fLen));
  }

  assertValidity() {
    if (!ge(r) || !ge(s)) {
      err('invalid signature');
    }
    return this;
  } // 0 < r or s < CURVE.n

  dynamic addRecoveryBit(int rec) {
    return Signature(r, s, rec);
  }

  bool hasHighS() {
    return moreThanHalfN(s);
  }

  Point recoverPublicKey(String msgh) {
    // ECDSA public key recovery
    if (![0, 1, 2, 3].contains(recover!)) err('recovery id invalid'); // check recovery id
    BigNumber h = bits2int_modN(Uint8List.fromList(convert.hex.decode(msgh))); // Truncate hash
    var radj = recover == 2 || recover == 3 ? r + N : r; // If rec was 2 or 3, q.x is bigger than n
    if (radj >= P) err('q.x invalid'); // ensure q.x is still a field element
    var head = (recover! & 1) == 0 ? '02' : '03'; // head is 0x02 or 0x03
    var R = Point.fromHex(head + n2h(radj)); // concat head + hex repr of r
    var ir = inv(radj, N); // r^-1
    var u1 = mod(h * BigNumber.NEGATIVE_ONE * ir, N); // -hr^-1
    var u2 = mod(s * ir, N); // sr^-1
    return G.mulAddQUns(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
  }

  Uint8List toCompactRawBytes() {
    return Uint8List.fromList(convert.hex.decode(toCompactHex()));
  } // Uint8Array 64b compact repr

  String toCompactHex() {
    return n2h(r) + n2h(s);
  }

  @override
  int get hashCode => _hex.hashCode;

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;

    if (other.runtimeType != runtimeType) return false;

    other as Signature;
    return r == other.r && s == other.s && recover == other.recover;
  }

  @override
  String toString() {
    return 'Signature {\n  r: $r,\n  s: $s,\n  recover: $recover\n}';
  }
}
