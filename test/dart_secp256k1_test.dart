// ignore_for_file: non_constant_identifier_names

import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'package:convert/convert.dart';
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

          String publicKey = getPublicKey(toBEHex(bn));
          Point point2 = Point.fromHex(publicKey);
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
    test('precompute', () {
      utils.precompute(4);
      var data = privatesTxt.split('\n').map((line) => line.split(':'));
      for (var p in data) {
        if (p.length == 3) {
          var priv = p[0], x = p[1], y = p[2];
          var bn = BigNumber.from(priv);

          var point = Point.fromPrivateKey(bn.toHexString());
          expect(toBEHex(point.x), x);
          expect(toBEHex(point.y), y);

          var point2 = Point.fromHex(getPublicKey(toBEHex(bn)));
          expect(toBEHex(point2.x), x);
          expect(toBEHex(point2.y), y);
        }
      }
    });

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
        Point point = Point.fromPrivateKey('0x${utils.randomHexString(64)}');
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

    group('Signature', () {
      test('.fromCompactHex() roundtrip', () {
        Point point = Point.fromPrivateKey('0x${utils.randomHexString(64)}');
        Signature sig = Signature(point.px, point.py);
        expect(Signature.fromCompact(sig.toCompactHex()), sig);
      });

      test('.fromDERHex() roundtrip', () {
        Point point = Point.fromPrivateKey('0x${utils.randomHexString(64)}');
        Signature sig = Signature(point.px, point.py);
        expect(sigFromDER(sigToDER(sig)), sig);
      });
    });

    group('sign()', () {
      test('create deterministic signatures with RFC 6979', () {
        for (var vector in ecdsa['valid']) {
          var usig = sign(vector['m'], vector['d']);
          var sig = usig.toCompactHex();
          var vsig = vector['signature'];
          expect(sig, vsig);
        }
      });

      test('not create invalid deterministic signatures with RFC 6979', () {
        for (var vector in ecdsa['invalid']['sign']) {
          expect(() => sign(vector['m'], vector['d']), throwsException);
        }
      });

      test('edge cases', () {
        expect(() => sign('', ''), throwsException);
      });

      test('create correct DER encoding against libsecp256k1', () {
        // ignore: constant_identifier_names
        const CASES = [
          [
            'd1a9dc8ed4e46a6a3e5e594615ca351d7d7ef44df1e4c94c1802f3592183794b',
            '304402203de2559fccb00c148574997f660e4d6f40605acc71267ee38101abf15ff467af02200950abdf40628fd13f547792ba2fc544681a485f2fdafb5c3b909a4df7350e6b'
          ],
          [
            '5f97983254982546d3976d905c6165033976ee449d300d0e382099fa74deaf82',
            '3045022100c046d9ff0bd2845b9aa9dff9f997ecebb31e52349f80fe5a5a869747d31dcb88022011f72be2a6d48fe716b825e4117747b397783df26914a58139c3f4c5cbb0e66c'
          ],
          [
            '0d7017a96b97cd9be21cf28aada639827b2814a654a478c81945857196187808',
            '3045022100d18990bba7832bb283e3ecf8700b67beb39acc73f4200ed1c331247c46edccc602202e5c8bbfe47ae159512c583b30a3fa86575cddc62527a03de7756517ae4c6c73'
          ]
        ];

        for (final testCase in CASES) {
          final msg = testCase[0];
          final exp = testCase[1];
          final res = sign(
            msg,
            '0101010101010101010101010101010101010101010101010101010101010101',
            opts: {'extraEntropy': null},
          );

          // expect(sigToDER(res), exp);
          var a = sigFromDER(sigToDER(res));
          final rs = sigFromDER(sigToDER(res)).toCompactHex();
          expect(sigToDER(Signature.fromCompact(rs)), exp);
        }
      });
    });
  });
}
