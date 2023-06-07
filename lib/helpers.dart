import 'dart:typed_data';

import 'package:convert/convert.dart' as convert;

import 'package:dart_bignumber/dart_bignumber.dart';
import 'package:dart_secp256k1/signature.dart';

class ParseResult {
  BigNumber d;
  Uint8List l;

  ParseResult(this.d, this.l);
}

class DER {
  static ParseResult parseInt(Uint8List data) {
    if (data.length < 2 || data[0] != 0x02) throw Exception('Invalid signature integer tag');
    final len = data[1];
    final res = data.sublist(2, len + 2);
    if (len == 0 || res.length != len) throw Exception('Invalid signature integer: wrong length');
    // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
    // since we always use positive integers here. It must always be empty:
    // - add zero byte if exists
    // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
    if (res[0] & 0x80 != 0) throw Exception('Invalid signature integer: negative');
    if (res[0] == 0x00 && res[1] & 0x80 == 0) throw Exception('Invalid signature integer: unnecessary leading zero');

    return ParseResult(BigNumber.from(res), data.sublist(len + 2));
  }

  static Signature toSig(String hex) {
    // if (!())
    var data = convert.hex.decode(hex);
    var l = data.length;
    if (l < 2 || data[0] != 0x30) throw Exception('ui8a expected');
    if (data[1] != l - 2) throw Exception('Invalid signature: incorrect length');

    ParseResult parseResult1 = parseInt(Uint8List.fromList(data.sublist(2)));
    BigNumber r = parseResult1.d;
    Uint8List sBytes = parseResult1.l;

    ParseResult parseResult2 = parseInt(sBytes);
    BigNumber s = parseResult2.d;
    Uint8List rBytesLeft = parseResult2.l;

    if (rBytesLeft.isNotEmpty) throw Exception('Invalid signature: left bytes after parsing');

    return Signature(r, s);
  }

  static String hexFromSig(Signature sig) {
    String slice(String s) {
      return (int.parse(s[0], radix: 16) >= 8) ? '00$s' : s; // slice DER
    }

    String h(n) {
      String hex = n.toRadixString(16);
      return (hex.length.isOdd) ? '0$hex' : hex;
    }

    String s = slice(sig.s.toHexString().substring(2));
    String r = slice(sig.r.toHexString().substring(2));
    int shl = s.length ~/ 2;
    int rhl = r.length ~/ 2;
    String sl = h(shl);
    String rl = h(rhl);
    return '30${h(rhl + shl + 4)}02$rl${r}02$sl$s';
  }
}

Signature sigFromDER(dynamic der) {
  final sig = DER.toSig(der);
  BigNumber r = sig.r;
  var s = sig.s;
  return Signature(r, s);
}

sigToDER(Signature sig) => DER.hexFromSig(sig);
