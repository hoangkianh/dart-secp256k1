// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:dart_bignumber/dart_bignumber.dart';
import 'package:dart_secp256k1/dart_secp256k1.dart';
import 'package:test/test.dart';

void main() {
  final file = File('test/vectors/points.json');
  var str = file.readAsStringSync();
  var points = jsonDecode(str);

  final privatesFile = File('test/vectors/privates.txt');
  var privatesTxt = privatesFile.readAsStringSync();

  String toBEHex(BigNumber n) => n.toHexString().replaceAll('0x', '').padLeft(64, '0');

  math.Random random = math.Random();
  String randomHexString(int length) {
    StringBuffer sb = StringBuffer();
    for (var i = 0; i < length; i++) {
      sb.write(random.nextInt(16).toRadixString(16));
    }
    return sb.toString();
  }

  List<String> INVALID_ITEMS = [
    'deadbeef',
    math.pow(2, 53).toString(),
    'xyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxyxyzxyzxy',
    (CURVE['n']! + BigNumber.TWO).toHexString()
  ];

  group('SECP256K1', () {
    test('getPublicKey()', () {
      var data = privatesTxt.split('\n').map((line) => line.split(':'));
      for (var p in data) {
        if (p.length == 3) {
          var priv = p[0], x = p[1], y = p[2];
          var bn = BigNumber.from(priv);

          Point point = Point.fromPrivateKey(bn.toHexString());
          expect(toBEHex(point.x), x);
          expect(toBEHex(point.y), y);

          String publicKey2 = getPublicKey(toBEHex(bn));
          Point point2 = Point.fromHex(publicKey2);
          expect(toBEHex(point2.x), x);
          expect(toBEHex(point2.y), y);
        }
      }
    });
    test('getPublicKey() rejects invalid keys', () {
      for (var item in INVALID_ITEMS) {
        expect(() => getPublicKey(item), throwsException);
      }
    });
    // should('precompute', () => {
    //   secp.utils.precompute(4);
    //   const data = privatesTxt
    //     .split('\n')
    //     .filter((line) => line)
    //     .map((line) => line.split(':'));
    //   for (let [priv, x, y] of data) {
    //     const point = Point.fromPrivateKey(BigInt(priv));
    //     deepStrictEqual(toBEHex(point.x), x);
    //     deepStrictEqual(toBEHex(point.y), y);

    //     const point2 = Point.fromHex(secp.getPublicKey(toBEHex(BigInt(priv))));
    //     deepStrictEqual(toBEHex(point2.x), x);
    //     deepStrictEqual(toBEHex(point2.y), y);

    //     const point3 = Point.fromHex(secp.getPublicKey(hexToBytes(toBEHex(BigInt(priv)))));
    //     deepStrictEqual(toBEHex(point3.x), x);
    //     deepStrictEqual(toBEHex(point3.y), y);
    //   }
    // });

    group('Point', () {
      test('fromHex() assertValidity', () async {
        for (var vector in points['valid']['isPoint']) {
          var P = vector['P'];
          var expected = vector['expected'];
          if (expected) {
            Point.fromHex(P);
          } else {
            expect(() => Point.fromHex(P), throwsException);
          }
        }
      });

      test('.fromPrivateKey()', () {
        for (var vector in points['valid']['pointFromScalar']) {
          Point p = Point.fromPrivateKey(vector['d']);
          expect(p.toHex(true), vector['expected']);
        }
      });

      test('#toHex(compressed)', () {
        for (var vector in points['valid']['pointCompress']) {
          var P = vector['P'];
          var compress = vector['compress'];
          var expected = vector['expected'];
          Point p = Point.fromHex(P);
          expect(p.toHex(compress), expected);
        }
      });

      test('#toHex() roundtrip (failed case)', () {
        var bn = BigNumber.from('88572218780422190464634044548753414301110513745532121983949500266768436236425');
        Point point1 = Point.fromPrivateKey(bn.toHexString());
        var hex = point1.toHex(true);
        expect(Point.fromHex(hex).toHex(true), hex);
      });

      test('#toHex() roundtrip', () {
        // randomize a point
        Point point = Point.fromPrivateKey('0x${randomHexString(64)}');
        var hex = point.toHex(true);
        expect(Point.fromHex(hex).toHex(true), hex);
      });

      test('#add(other)', () {
        for (var vector in points['valid']['pointAdd']) {
          var P = vector['P'], Q = vector['Q'], expected = vector['expected'];
          Point p = Point.fromHex(P);
          Point q = Point.fromHex(Q);
          if (expected != null) {
            expect(p.add(q).toHex(true), expected);
          } else {
            if (!p.equals(q.negate())) {
              expect(() => p.add(q).toHex(true), throwsException);
            }
          }
        }
      });

      test('#multiply(privateKey)', () {
        for (var vector in points['valid']['pointMultiply']) {
          var P = vector['P'], d = vector['d'], expected = vector['expected'];
          Point p = Point.fromHex(P);
          if (expected != null) {
            expect(p.multiply(BigNumber.from(d)).toHex(true), expected);
          } else {
            expect(p.multiply(BigNumber.from(d)).toHex(true), throwsException);
          }
        }

        for (var vector in points['invalid']['pointMultiply']) {
          var P = vector['P'], d = vector['d'];
          BigNumber dBN = BigNumber.from('0x$d');
          BigNumber n = CURVE['n'] ?? BigNumber.ZERO;

          if (dBN < n) {
            expect(() {
              Point p = Point.fromHex(P);
              p.multiply(BigNumber.from(d)).toHex(true);
            }, throwsException);
          }
        }

        for (var n in [0, 0, -1, -1, 1.1]) {
          expect(() => Point.BASE.multiply(BigNumber.from(n)), throwsException);
        }
      });
    });
  });
}
