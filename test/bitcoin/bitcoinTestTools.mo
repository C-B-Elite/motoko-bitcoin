import Affine "../../src/ec/Affine";
import Jacobi "../../src/ec/Jacobi";
import Curves "../../src/ec/Curves";
import Hash "../../src/Hash";
import Fp "../../src/ec/Fp";
import PublicKey "../../src/ecdsa/Publickey";
import Types "../../src/bitcoin/Types";
import P2pkh "../../src/bitcoin/P2pkh";
import Common "../../src/Common";
import Debug "mo:base/Debug";
import Array "mo:base/Array";
import Nat8 "mo:base/Nat8";
import Iter "mo:base/Iter";
import Buffer "mo:base/Buffer";

module {
  public type Signature = {r : Nat; s : Nat};
  let curve = Curves.secp256k1;

  // Helper class for generating public key and addresses based on the given
  // secp256k1 secret key.
  public class Account(_sk : Nat) {
    public let sk : Nat = _sk;
    public let point = Jacobi.toAffine(Jacobi.mulBase(sk, Curves.secp256k1));
    public let pkData = Affine.toBytes(point, true);
    public let pk = switch(PublicKey.decode(#point (point))) {
      case (#ok(pk)) {
        pk;
      };
      case (_) {
        Debug.trap("Invalid");
      }
    };
    public let p2pkhAddress = P2pkh.deriveAddress(#Bitcoin, pk);
  };

  // Helper function for operating modulo the curve order.
  func Fr(value : Nat) : Fp.Fp {
    return Fp.Fp(value, curve.r);
  };

  // ECDSA signing for testing transaction signatures.
  public func ecdsaSign(sk : Nat, rand : Nat, message : [Nat8]) : Signature {
    let h = Common.readBE256(Hash.doubleSHA256(message), 0);
    switch(Jacobi.toAffine(Jacobi.mulBase(rand, Curves.secp256k1))) {
      case (#point (x, y, curve)) {
        let r = x.value;
        if (r == 0) {
          Debug.trap("r = 0, use different rand.");
        };
        let s = Fr(rand).inverse().mul(
          Fr(h + sk * r)
        );
        if (s.value == 0) {
          Debug.trap("s = 0, use different rand.");
        };

        let finalS = if (s.value > curve.r/2) {
          curve.r - s.value
        } else {
          s.value
        };

        return {r = r; s = finalS};
      };
      case (#infinity (_)) {
        Debug.trap("Computed infinity point, use different rand.");
      };
    };
  };

  // Serialize signature to DER format:
  // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash-type]
  public func signatureToDer(signature : Signature,
    sighashType : Types.SighashType) : [Nat8] {

    func prepSignatureMember(value : Nat) : [Nat8] {
      let data = Array.init<Nat8>(32, 0);
      Common.writeBE256(data, 0, value);
      var startOffset = 0;
      label L for (i in Iter.range(0, data.size() - 1)) {
        if (data[i] == 0) {
          startOffset += 1;
        } else {
          break L;
        };
      };
      // Prepend zero if most significant bit is set since integers in DER are
      // signed.
      let prependZero : Bool = data[startOffset] >= 0x80;
      let totalSize = if (prependZero) {
        data.size() - startOffset + 1
      } else {
        data.size() - startOffset
      };

      // Return data with zeroes ommitted, except for an initial zero if the
      // MSB in the first byte is set.
      return Array.tabulate<Nat8>(totalSize, func (i) {
        if (prependZero) {
          if (i == 0) {
            0x00;
          } else {
            data[startOffset + i - 1]
          };
        } else {
          data[startOffset + i]
        };
      });
    };

    let output = Buffer.Buffer<Nat8>(0);
    let rData : [Nat8] = prepSignatureMember(signature.r);
    let sData : [Nat8] = prepSignatureMember(signature.s);

    // Add DER identifier.
    output.add(0x30);
    // Total size of everything that comes next, excluding sighash type.
    output.add(Nat8.fromIntWrap(
      // DER Sequence identifier: 0x02.
      1
      // Signature r component size.
      + 1
      // Signature r component.
      + rData.size()
      // DER Sequence identifier : 0x02.
      + 1
      // Signature s component size.
      + 1
      // Signature s component.
      + sData.size()
    ));
    // DER sequence identifier.
    output.add(0x02);
    // Signature r component size.
    output.add(Nat8.fromIntWrap(rData.size()));

    // Signature r component.
    for (i in rData.vals()) {
      output.add(i);
    };

    // DER sequence identifier.
    output.add(0x02);
    // Signature s component size.
    output.add(Nat8.fromIntWrap(sData.size()));

    // Signature s component.
    for (i in sData.vals()) {
      output.add(i);
    };

    // sighashtype
    output.add(0x01);

    return output.toArray();
  };
};
