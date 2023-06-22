// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';
import 'package:dart_bignumber/dart_bignumber.dart';
import 'package:crypto/crypto.dart' as crypto;

import 'main.dart';
import 'point.dart';
import 'utils.dart';

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
    var bytes = toU8(hex);
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
    BigNumber h = bits2int_modN(toU8(msgh)); // Truncate hash
    var radj = recover == 2 || recover == 3 ? r + N : r; // If rec was 2 or 3, q.x is bigger than n
    if (radj >= P) err('q.x invalid'); // ensure q.x is still a field element
    var head = (recover! & 1) == 0 ? '02' : '03'; // head is 0x02 or 0x03
    var R = Point.fromHex(head + n2h(radj)); // concat head + hex repr of r
    var ir = inv(radj, N); // r^-1
    var u1 = mod(-h * ir, N); // -hr^-1
    var u2 = mod(s * ir, N); // sr^-1
    return G.mulAddQUns(R, u1, u2); // (sr^-1)R-(hr^-1)G = -(hr^-1)G + (sr^-1)
  }

  Uint8List toCompactRawBytes() {
    return toU8(toCompactHex());
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

BigNumber bits2BigNumber(Uint8List bytes) {
  // RFC6979: ensure ECDSA msg is X bytes.
  int delta = bytes.length * 8 - 256; // RFC suggests optional truncating via bits2octets
  BigNumber n = b2n(bytes); // FIPS 186-4 4.6 suggests the leftmost min(nBitLen, outLen) bits, which
  return delta > 0 ? n >> delta : n; // matches bits2int. bits2int can produce res>N.
}

BigNumber bits2BigNumber_modN(Uint8List bytes) {
  // int2octets can't be used; pads small msgs
  return mod(bits2BigNumber(bytes), N); // with 0: BAD for trunc as per RFC vectors
}

List<int> i2o(BigNumber n) => n2b(n); // int to octets

// declare const globalThis: Record<string, any> | undefined; // Typescript symbol present in browsers
Map<String, dynamic>? globalThis;
Map<String, dynamic>? cr() => globalThis != null && globalThis is Map<String, dynamic> && globalThis!.containsKey('crypto') ? globalThis!['crypto'] : null;
typedef HmacFnSync = Uint8List? Function(Uint8List key, Uint8List msgs);
typedef K2SigCallback = Signature? Function(Uint8List kb);
final optS = {'lowS': true, 'extraEntropy': null}; // opts for sign()
final optV = {'lowS': true}; // standard opts for verify()

class BC {
  Uint8List seed;
  K2SigCallback k2sig;

  BC(this.seed, this.k2sig);
}

BC prepSig(String msgh, String priv, {Map<String, dynamic>? opts}) {
  opts ??= optS;

  if (['der', 'recovered', 'canonical'].any((k) => opts!.containsKey(k))) {
    throw Exception('sign() legacy options not supported');
  }

  bool lowS = opts['lowS'] ?? true;
  BigNumber h1i = bits2BigNumber_modN(toU8(msgh));
  List<int> h1o = i2o(h1i);
  BigNumber d = toPriv(BigNumber.from(priv.contains('0x') ? priv : '0x$priv'));
  List<int> seed = i2o(d) + h1o;
  var ent = opts['extraEntropy'];
  if (ent != null) {
    if (ent is bool && ent == true) {
      ent = randomHexString(fLen);
    }
    List<int> e = toU8(ent);
    if (e.length != fLen) {
      throw Exception('Expected 32 bytes of extra data');
    }
    seed += e;
  }

  BigNumber m = h1i;

  Signature? k2sig(Uint8List kBytes) {
    // Transform k => Signature.
    BigNumber k = bits2BigNumber(kBytes); // RFC6979 method.
    if (!ge(k)) {
      // Check 0 < k < CURVE.n
      return null;
    }

    BigNumber ik = inv(k, N); // k^-1 mod n, NOT mod P
    AffinePoint q = G.mul(k).aff(); // q = Gk
    BigNumber r = mod(q.x, N);
    if (r.isZero()) {
      return null; // r=0 invalid
    }
    BigNumber s = mod(ik * mod(m + mod(d * r, N), N), N); // s = k^-1(m + rd) mod n
    if (s.isZero()) {
      return null;
    } // s=0 invalid
    BigNumber normS = s; // normalized S
    int rec = (q.x == r ? 0 : 2) | int.parse((q.y & BigNumber.ONE).toString()); // recovery bit
    if (lowS && moreThanHalfN(s)) {
      // if lowS was passed, ensure s is always
      normS = mod(-s, N); // in the bottom half of CURVE.n
      rec ^= 1;
    }
    return Signature(r, normS, rec); // use normS, not s
  }

  return BC(Uint8List.fromList(seed), k2sig);
}

typedef Pred<T> = T? Function(Uint8List v);

Uint8List hmacSha256(Uint8List key, List<Uint8List> msgs) {
  final hmac = crypto.Hmac(crypto.sha256, key);
  final data = msgs.fold<Uint8List>(Uint8List(0), (previousValue, element) => Uint8List.fromList([...previousValue, ...element]));
  final digest = hmac.convert(data);
  return Uint8List.fromList(digest.bytes);
}

Function hmacDrbg<T>(bool asynchronous) {
  Uint8List v = Uint8List(fLen); // Minimal non-full-spec HMAC-DRBG from NIST 800-90 for RFC6979 sigs.
  Uint8List k = Uint8List(fLen); // Steps B, C of RFC6979 3.2: set hashLen, in our case always same
  int i = 0; // Iterations counter, will throw when over 1000

  void reset() {
    v.fillRange(0, v.length, 1);
    k.fillRange(0, k.length, 0);
    i = 0;
  }

  final String error = 'drbg: tried 1000 values';
  Uint8List h(Uint8List b) => hmacSha256(k, [v, b]);

  reseed(Uint8List seed) {
    k = h(Uint8List.fromList([0x00, ...seed])); // k = hmac(k || v || 0x00 || seed)
    v = h(Uint8List(0)); // v = hmac(k || v)
    if (seed.isEmpty) return;
    k = h(Uint8List.fromList([0x01, ...seed])); // k = hmac(k || v || 0x01 || seed)
    v = h(Uint8List(0)); // v = hmac(k || v)
  }

  Uint8List gen() {
    if (i++ >= 1000) throw Exception(error);
    v = h(Uint8List(0)); // v = hmac(k || v)
    return v;
  }

  return (Uint8List seed, Pred<T> pred) {
    reset();
    reseed(seed);
    T? res;
    while ((res = pred(gen())) == null) {
      reseed(Uint8List(0));
    }
    reset();
    return res!;
  };
}

Signature sign(String msgh, String priv, {Map<String, dynamic>? opts = const {'lowS': true}}) {
  final BC bc = prepSig(msgh, priv, opts: opts);
  final seed = bc.seed;
  final k2sig = bc.k2sig;
  return hmacDrbg<Signature>(false)(seed, k2sig);
}

bool verify(String sig, String msgh, String pub, {Map<String, dynamic>? opts = const {'lowS': true}}) {
  opts ?? optV;
  bool lowS = opts!['lowS'];

  if (opts.containsKey('strict')) err('verify() legacy options not supported');

  Signature sig_;
  BigNumber h;
  Point P;

  try {
    sig_ = Signature.fromCompact(sig);
    h = bits2BigNumber_modN(toU8(msgh));
    P = Point.fromHex(pub);
  } catch (e) {
    return false;
  }

  BigNumber r = sig_.r;
  BigNumber s = sig_.s;

  if (lowS && moreThanHalfN(s)) {
    return false;
  }

  AffinePoint R;
  try {
    BigNumber is_ = inv(s, N); // s^-1
    BigNumber u1 = mod(h * is_, N); // u1 = hs^-1 mod n
    BigNumber u2 = mod(r * is_, N); // u2 = rs^-1 mod n
    R = G.mulAddQUns(P, u1, u2).aff(); // R = u1⋅G + u2⋅P
  } catch (e) {
    print(e);
    return false;
  }

  if (R.x.isZero() && R.y.isZero()) return false; // stop if R is identity / zero point
  BigNumber v = mod(R.x, N);  // <== The weird ECDSA part. R.x must be in N's field, not P's
  return v == r; // mod(R.x, n) == r
}
