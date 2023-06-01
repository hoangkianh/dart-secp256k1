import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:dart_bignumber/dart_bignumber.dart';
import 'package:dart_secp256k1/dart_secp256k1.dart';
import 'package:test/test.dart';

void main() {
  final file = File('test/vectors/points.json');
  var str = file.readAsStringSync();
  var points = jsonDecode(str);

  Random _random = Random();
  String randomHexString(int length) {
    StringBuffer sb = StringBuffer();
    for (var i = 0; i < length; i++) {
      sb.write(_random.nextInt(16).toRadixString(16));
    }
    return sb.toString();
  }

  group('SECP256K1', () {
    //   should('getPublicKey()', () => {
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
    // should('getPublicKey() rejects invalid keys', () => {
    //   for (const item of INVALID_ITEMS) {
    //     throws(() => secp.getPublicKey(item));
    //   }
    // });
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
        Point point1 = Point.fromPrivateKey(
            '0xC3D2196ACDC1DB254EC4D80D6158CDC24529A9D6629A29B1578A66C088A71089'
                .toLowerCase());
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
