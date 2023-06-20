import 'dart:typed_data';
import 'dart:math' as math;

import 'package:dart_bignumber/dart_bignumber.dart';

import 'main.dart';
import 'point.dart';

bool isValidPrivateKey(String key) {
  try {
    toPriv(BigNumber.from(key));
    return true;
  } catch (e) {
    return false;
  }
}

math.Random random = math.Random();

List<int> randomBytes(int length) {
  final random = math.Random.secure();
  final bytes = List<int>.generate(length, (_) => random.nextInt(256));
  return bytes;
}

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
