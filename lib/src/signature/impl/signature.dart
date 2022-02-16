import 'dart:typed_data';

import 'package:equatable/equatable.dart';
import 'package:meta/meta.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:tezart/src/common/validators/hex_validator.dart';
import 'package:tezart/src/keystore/keystore.dart';

import 'package:tezart/src/crypto/crypto.dart' as crypto;
import 'package:tezart/src/models/operations_list/impl/operations_list.dart';

enum Watermarks {
  block,
  endorsement,
  generic,
}

/// A class that takes data of different types and signs it using a [Keystore] object.\
///
/// It can sign bytes and hexadecimal data.\
/// The signature is computed in different formats:
/// - [signedBytes]: signed bytes
/// - [edsig]: base 58 encoded using 'edsig' prefix
/// - [hexIncludingPayload]: hexadecimal signature prefixed by data to sign
@immutable
class Signature extends Equatable {
  final Uint8List bytes;
  final Keystore? keystore;
  final Watermarks? watermark;
  final SignCallback? onSign;

  static final _watermarkToHex = {
    Watermarks.block: '01',
    Watermarks.endorsement: '02',
    Watermarks.generic: '03',
  };

  Signature._({
    required this.bytes,
    this.keystore,
    this.watermark,
    this.onSign,
  });

  /// A factory that computes the signature of [bytes] (prefixed by [watermark]) using [keystore].
  ///
  /// [watermark] is optional and will be ignored if missing.
  factory Signature.fromBytes({
    required Uint8List bytes,
    Keystore? keystore,
    Watermarks? watermark,
    SignCallback? onSign,
  }) {
    return Signature._(
      bytes: bytes,
      watermark: watermark,
      keystore: keystore,
      onSign: onSign,
    );
  }

  /// A factory that computes the signature of hexadecimal [data] (prefixed by [watermark]) using [keystore].\
  ///
  /// [watermark] is optional and will be ignored if missing.\
  /// Throws a [CryptoError] if :
  /// - [data] is not hexadecimal
  /// - [data] length is odd (because it must be the hexadecimal of a list of bytes (a single byte represent two hexadecimal digits))
  factory Signature.fromHex({
    required String data,
    Keystore? keystore,
    Watermarks? watermark,
    SignCallback? onSign,
  }) {
    return crypto.catchUnhandledErrors(() {
      HexValidator(data).validate();
      // Because two hexadecimal digits correspond to a single byte, this will throw an error if the length of the data is odd
      if (data.length.isOdd) {
        throw crypto.CryptoError(
            type: crypto.CryptoErrorTypes.invalidHexDataLength);
      }
      var bytes = crypto.hexDecode(data);

      return Signature.fromBytes(
        bytes: bytes,
        keystore: keystore,
        watermark: watermark,
        onSign: onSign,
      );
    });
  }

  /// Signed bytes of this.
  ByteList get signedBytes {
    return crypto.catchUnhandledErrors(() {
      final watermarkedBytes = watermark == null
          ? bytes
          : Uint8List.fromList(
              crypto.hexDecode(_watermarkToHex[watermark]!) + bytes);
      var hashedBytes =
          crypto.hashWithDigestSize(size: 256, bytes: watermarkedBytes);
      var secretKey = keystore!.secretKey;
      var secretKeyBytes = crypto.decodeWithoutPrefix(secretKey);

      return crypto.signDetached(bytes: hashedBytes, secretKey: secretKeyBytes);
    });
  }

  Future<Uint8List> get signedHex async {
    return crypto.catchUnhandledErrors(() {
      final watermarkedBytes = watermark == null
          ? bytes
          : Uint8List.fromList(
              crypto.hexDecode(_watermarkToHex[watermark]!) + bytes);
      var hashedBytes =
          crypto.hashWithDigestSize(size: 256, bytes: watermarkedBytes);
      return onSign!.call(hashedBytes);
    });
  }

  /// Base 58 encoding of this using 'edsig' prefix.
  Future<String> get edsig async {
    return crypto.catchUnhandledErrors(() async {
      Uint8List bytes;
      if (onSign != null) {
        bytes = await signedHex;
      } else {
        bytes = Uint8List.fromList(signedBytes.toList());
      }

      return crypto.encodeWithPrefix(
          prefix: crypto.Prefixes.edsig, bytes: bytes);
    });
  }

  /// Hexadecimal signature of this prefixed with hexadecimal payload to sign.
  Future<String> get hexIncludingPayload async {
    return crypto.catchUnhandledErrors(() async {
      ByteList tempSignedBytes;
      if (onSign != null) {
        final data = await signedHex;
        tempSignedBytes = ByteList.fromList(data);
      } else {
        tempSignedBytes = signedBytes;
      }
      return crypto.hexEncode(Uint8List.fromList(bytes + tempSignedBytes));
    });
  }

  @override
  List<Object> get props => [signedBytes];
}
