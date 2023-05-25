import 'dart:convert';
import 'dart:io';
import 'package:dart_secp256k1/dart_secp256k1.dart';
import 'package:test/test.dart';

void main() {
  final file = File('test/vectors/points.json');
  var str = file.readAsStringSync();
  var points = jsonDecode(str);

  group('SECP256K1', () {
    test('getPublicKey()', () {});

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

      // should('.fromPrivateKey()', () => {
      //   for (const vector of points.valid.pointFromScalar) {
      //     const { d, expected } = vector;
      //     let p = Point.fromPrivateKey(d);
      //     deepStrictEqual(p.toHex(true), expected);
      //   }
      // });

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
        // var point1 =
        //   Point.fromPrivateKey(
        //     88572218780422190464634044548753414301110513745532121983949500266768436236425n
        //   );
        // const hex = point1.toHex(true);
        // deepStrictEqual(Point.fromHex(hex).toHex(true), hex);
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
