// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'package:dart_secp256k1/helpers.dart';
import 'package:dart_secp256k1/signature.dart';
import 'package:test/test.dart';

import 'package:dart_bignumber/dart_bignumber.dart';
import 'package:dart_secp256k1/main.dart';
import 'package:dart_secp256k1/point.dart';
import 'package:dart_secp256k1/utils.dart' as utils;

void main() {
  final points_file = File('test/vectors/points.json');
  var str = points_file.readAsStringSync();
  var points = jsonDecode(str);

  final ecdsa_file = File('test/vectors/ecdsa.json');
  str = ecdsa_file.readAsStringSync();
  var ecdsa = jsonDecode(str);

  final privatesFile = File('test/vectors/privates.txt');
  var privatesTxt = privatesFile.readAsStringSync();

  String toBEHex(BigNumber n) => n.toHexString().replaceAll('0x', '').padLeft(64, '0');

  List<String> INVALID_ITEMS = ['deadbeef', math.pow(2, 53).toString(), 'xyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxy', (CURVE['n']! + BigNumber.TWO).toHexString()];

  // group('SECP256K1', () {
  // test('getPublicKey()', () {
  //   var data = privatesTxt.split('\n').map((line) => line.split(':'));
  //   for (var p in data) {
  //     if (p.length == 3) {
  //       var priv = p[0], x = p[1], y = p[2];
  //       var bn = BigNumber.from(priv);

  //       Point point = Point.fromPrivateKey(bn.toHexString());
  //       expect(toBEHex(point.x), x);
  //       expect(toBEHex(point.y), y);

  //       String publicKey = getPublicKey(toBEHex(bn));
  //       Point point2 = Point.fromHex(publicKey);
  //       expect(toBEHex(point2.x), x);
  //       expect(toBEHex(point2.y), y);
  //     }
  //   }
  // });
  // test('getPublicKey() rejects invalid keys', () {
  //   for (var item in INVALID_ITEMS) {
  //     expect(() => getPublicKey(item), throwsException);
  //   }
  // });
  // test('precompute', () {
  //   utils.precompute(4);
  //   var data = privatesTxt.split('\n').map((line) => line.split(':'));
  //   for (var p in data) {
  //     if (p.length == 3) {
  //       var priv = p[0], x = p[1], y = p[2];
  //       var bn = BigNumber.from(priv);

  //       var point = Point.fromPrivateKey(bn.toHexString());
  //       expect(toBEHex(point.x), x);
  //       expect(toBEHex(point.y), y);

  //       var point2 = Point.fromHex(getPublicKey(toBEHex(bn)));
  //       expect(toBEHex(point2.x), x);
  //       expect(toBEHex(point2.y), y);
  //     }
  //   }
  // });

  // group('Point', () {
  //   test('fromHex() assertValidity', () async {
  //     for (var vector in points['valid']['isPoint']) {
  //       var P = vector['P'];
  //       var expected = vector['expected'];
  //       if (expected) {
  //         Point.fromHex(P);
  //       } else {
  //         expect(() => Point.fromHex(P), throwsException);
  //       }
  //     }
  //   });

  //   test('.fromPrivateKey()', () {
  //     for (var vector in points['valid']['pointFromScalar']) {
  //       Point p = Point.fromPrivateKey(vector['d']);
  //       expect(p.toHex(true), vector['expected']);
  //     }
  //   });

  //   test('#toHex(compressed)', () {
  //     for (var vector in points['valid']['pointCompress']) {
  //       var P = vector['P'];
  //       var compress = vector['compress'];
  //       var expected = vector['expected'];
  //       Point p = Point.fromHex(P);
  //       expect(p.toHex(compress), expected);
  //     }
  //   });

  //   test('#toHex() roundtrip (failed case)', () {
  //     var bn = BigNumber.from('88572218780422190464634044548753414301110513745532121983949500266768436236425');
  //     Point point1 = Point.fromPrivateKey(bn.toHexString());
  //     var hex = point1.toHex(true);
  //     expect(Point.fromHex(hex).toHex(true), hex);
  //   });

  //   test('#toHex() roundtrip', () {
  //     // randomize a point
  //     Point point = Point.fromPrivateKey('0x${utils.randomHexString(64)}');
  //     var hex = point.toHex(true);
  //     expect(Point.fromHex(hex).toHex(true), hex);
  //   });

  //   test('#add(other)', () {
  //     for (var vector in points['valid']['pointAdd']) {
  //       var P = vector['P'], Q = vector['Q'], expected = vector['expected'];
  //       Point p = Point.fromHex(P);
  //       Point q = Point.fromHex(Q);
  //       if (expected != null) {
  //         expect(p.add(q).toHex(true), expected);
  //       } else {
  //         if (!p.equals(q.negate())) {
  //           expect(() => p.add(q).toHex(true), throwsException);
  //         }
  //       }
  //     }
  //   });

  //   test('#multiply(privateKey)', () {
  //     for (var vector in points['valid']['pointMultiply']) {
  //       var P = vector['P'], d = vector['d'], expected = vector['expected'];
  //       Point p = Point.fromHex(P);
  //       if (expected != null) {
  //         expect(p.multiply(BigNumber.from(d)).toHex(true), expected);
  //       } else {
  //         expect(p.multiply(BigNumber.from(d)).toHex(true), throwsException);
  //       }
  //     }

  //     for (var vector in points['invalid']['pointMultiply']) {
  //       var P = vector['P'], d = vector['d'];
  //       BigNumber dBN = BigNumber.from('0x$d');
  //       BigNumber n = CURVE['n'] ?? BigNumber.ZERO;

  //       if (dBN < n) {
  //         expect(() {
  //           Point p = Point.fromHex(P);
  //           p.multiply(BigNumber.from(d)).toHex(true);
  //         }, throwsException);
  //       }
  //     }

  //     for (var n in [0, 0, -1, -1, 1.1]) {
  //       expect(() => Point.BASE.multiply(BigNumber.from(n)), throwsException);
  //     }
  //   });
  // });

  group('Signature', () {
    //   test('.fromCompactHex() roundtrip', () {
    //     Point point = Point.fromPrivateKey('0x${utils.randomHexString(64)}');
    //     Signature sig = Signature(point.px, point.py);
    //     expect(Signature.fromCompact(sig.toCompactHex()), sig);
    //   });

    //   test('.fromDERHex() roundtrip', () {
    //     Point point = Point.fromPrivateKey('0x${utils.randomHexString(64)}');
    //     Signature sig = Signature(point.px, point.py);
    //     expect(sigFromDER(sigToDER(sig)), sig);
    //   });
    // });

    group('sign()', () {
      test('create deterministic signatures with RFC 6979', () {
        for (var vector in ecdsa['valid']) {
          var usig = sign(vector['m'], vector['d']);
          var sig = usig.toCompactHex();
          var vsig = vector['signature'];
          expect(sig, vsig);
          //   deepStrictEqual(sig.slice(0, 64), vsig.slice(0, 64));
          //   deepStrictEqual(sig.slice(64, 128), vsig.slice(64, 128));
        }
      });
    });
  });
}
