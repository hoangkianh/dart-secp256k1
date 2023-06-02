import 'dart:typed_data';
import 'dart:math' as math;

import 'package:dart_bignumber/dart_bignumber.dart';
import 'package:dart_secp256k1/dart_secp256k1.dart';
import 'package:dart_secp256k1/point.dart';

bool isValidPrivateKey(String key) {
  try {
    toPriv(BigNumber.from(key));
    return true;
  } catch (e) {
    return false;
  }
}

math.Random random = math.Random();

String randomHexString(int length) {
  StringBuffer sb = StringBuffer();
  for (var i = 0; i < length; i++) {
    sb.write(random.nextInt(16).toRadixString(16));
  }
  return sb.toString();
}

Uint8List randomPrivateKey() {
  return hashToPrivateKey(randomHexString(fLen + 8));
}

Point precompute([int w = 8, Point? p]) {
  Point p1 = G;
  if (p != null) {
    p1 = p;
  }

  return p1.multiply(BigNumber.from(3));
}
