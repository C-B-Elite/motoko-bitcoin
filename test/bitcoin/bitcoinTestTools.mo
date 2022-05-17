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


module {
  public type Signature = {r : Nat; s : Nat};
  let curve = Curves.secp256k1;

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

  func Fr(value : Nat) : Fp.Fp {
    return Fp.Fp(value, curve.r);
  };

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

  public func signatureToDer(signature : Signature,
    sighashType : Types.SighashType) : [Nat8] {
    // 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash-type]

    func prepSignatureMember(value : Nat) : ([Nat8], Nat, Nat, Bool) {
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
      let prependZero : Bool = data[startOffset] >= 0x80;
      let totalSize = if (prependZero) {
        data.size() - startOffset + 1
      } else {
        data.size() - startOffset
      };
      return (Array.freeze(data), startOffset, totalSize, prependZero);
    };

    let (rData, rStartOffset, rTotalSize,
      rPrependZero) = prepSignatureMember(signature.r);

    let (sData, sStartOffset, sTotalSize,
      sPrependZero) = prepSignatureMember(signature.s);

    let totalSize = 1 + 1 + 1 + 1 + rTotalSize + 1 + 1 + sTotalSize + 1;
    let output = Array.init<Nat8>(totalSize, 0);
    var writeOffset = 0;

    output[0] := 0x30;
    // Total size excluding first bytes, total size byte, and sighash type
    output[1] := Nat8.fromIntWrap(totalSize - 3);
    output[2] := 0x02;
    output[3] := Nat8.fromIntWrap(rTotalSize);
    writeOffset := 4;

    if (rPrependZero) {
      output[writeOffset] := 0;
      writeOffset += 1;
    };

    let rDataLength = rData.size() - rStartOffset;
    Common.copy(output, writeOffset, rData, rStartOffset, rDataLength);
    writeOffset += rDataLength;

    output[writeOffset] := 0x02;
    writeOffset += 1;

    output[writeOffset] := Nat8.fromIntWrap(sTotalSize);
    writeOffset += 1;

    if (sPrependZero) {
      output[writeOffset] := 0;
      writeOffset += 1;
    };

    let sDataLength = sData.size() - sStartOffset;
    Common.copy(output, writeOffset, sData, sStartOffset, sDataLength);
    writeOffset += sDataLength;

    // sighashtype
    output[writeOffset] := 0x01;
    writeOffset += 1;

    assert(writeOffset == output.size());
    return Array.freeze(output);
  };
};
