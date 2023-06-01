import 'dart:convert';
import 'dart:io';
import 'package:dart_secp256k1/dart_secp256k1.dart';
import 'package:test/test.dart';

void main() {
  final file = File('test/vectors/points.json');
  var str = file.readAsStringSync();
  var points = jsonDecode(str);

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
          var p = Point.fromPrivateKey(vector['d']);
          expect(p.toHex(true), vector['expected']);
        }
      });

      test('#toHex(compressed)', () {
        for (var vector in points['valid']['pointCompress']) {
          var P = vector['P'];
          var compress = vector['compress'];
          var expected = vector['expected'];
          var p = Point.fromHex(P);
          expect(p.toHex(compress), expected);
        }
      });

      test('#toHex() roundtrip (failed case)', () {
        var point1 =
          Point.fromPrivateKey(
            '0xC3D2196ACDC1DB254EC4D80D6158CDC24529A9D6629A29B1578A66C088A71089'.toLowerCase()
          );
        var hex = point1.toHex(true);
        expect(Point.fromHex(hex).toHex(true), hex);
      });

      // should('#toHex() roundtrip', () => {
      //   fc.assert(
      //     fc.property(FC_BIGINT, (x) => {
      //       const point1 = Point.fromPrivateKey(x);
      //       const hex = point1.toHex(true);
      //       deepStrictEqual(Point.fromHex(hex).toHex(true), hex);
      //     })
      //   );
      // });

      // should('#add(other)', () => {
      //   for (const vector of points.valid.pointAdd) {
      //     const { P, Q, expected } = vector;
      //     let p = Point.fromHex(P);
      //     let q = Point.fromHex(Q);
      //     if (expected) {
      //       deepStrictEqual(p.add(q).toHex(true), expected);
      //     } else {
      //       if (!p.equals(q.negate())) {
      //         throws(() => p.add(q).toHex(true));
      //       }
      //     }
      //   }
      // });

      // should('#multiply(privateKey)', () => {
      //   for (const vector of points.valid.pointMultiply) {
      //     const { P, d, expected } = vector;
      //     const p = Point.fromHex(P);
      //     if (expected) {
      //       deepStrictEqual(p.multiply(hexToNumber(d)).toHex(true), expected, P);
      //     } else {
      //       throws(() => {
      //         p.multiply(hexToNumber(d)).toHex(true);
      //       });
      //     }
      //   }

      //   for (const vector of points.invalid.pointMultiply) {
      //     const { P, d } = vector;
      //     if (hexToNumber(d) < secp.CURVE.n) {
      //       throws(() => {
      //         const p = Point.fromHex(P);
      //         p.multiply(hexToNumber(d)).toHex(true);
      //       });
      //     }
      //   }
      //   for (const num of [0n, 0, -1n, -1, 1.1]) {
      //     throws(() => Point.BASE.multiply(num));
      //   }
      // });
    });
  });
}
