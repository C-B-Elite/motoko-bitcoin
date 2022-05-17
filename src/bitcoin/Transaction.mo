import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Nat32 "mo:base/Nat32";
import Blob "mo:base/Blob";
import Hash "../Hash";
import Script "./Script";
import Common "../Common";
import Types "./Types";

module {
  // Representation of a TxIn of a Bitcoin transaction. A TxIn is linked to a
  // previous transaction output given by prevOutput.
  public class TxIn(prevOutput : Types.OutPoint, sequence : Nat32) {

    // Unlocking script. This is mutuable to enable signature hash construction
    // for a transaction without having to clone the transaction.
    public var script : Script.Script = [];

    // Serialize to bytes with layout:
    // | prevTxId | prevTx output index | script | sequence |.
    public func toBytes() : [Nat8] {
      let encodedScript = Script.toBytes(script);
      // Total size based on output layout.
      let totalSize = 32 + 4 + encodedScript.size() + 4;
      let output = Array.init<Nat8>(totalSize, 0);
      var outputOffset = 0;

      let prevTxId = Blob.toArray(prevOutput.txid);
      let reversedPrevTxid = Array.tabulate<Nat8>(32, func (n : Nat) {
        prevTxId[prevTxId.size() - 1 - n];
      });

      // Write prevTxId.
      Common.copy(output, outputOffset, reversedPrevTxid, 0, 32);
      outputOffset += 32;

      // Write prevTx output index.
      Common.writeLE32(output, outputOffset, prevOutput.vout);
      outputOffset += 4;

      // Write script.
      Common.copy(output, outputOffset, encodedScript, 0, encodedScript.size());
      outputOffset += encodedScript.size();

      // Write sequence.
      Common.writeLE32(output, outputOffset, sequence);
      outputOffset += 4;

      assert(outputOffset == output.size());
      return Array.freeze(output);
    };
  };

  // Representation of a TxOut of a Bitcoin transaction. A TxOut locks
  // specified amount with the given script.
  public class TxOut(amount : Types.Satoshi, scriptPubKey : Script.Script) {

    // Serialize to bytes with layout: | amount | serialized script |.
    public func toBytes() : [Nat8] {
      let encodedScript = Script.toBytes(scriptPubKey);
      let totalSize = 8 + encodedScript.size();
      let output = Array.init<Nat8>(totalSize, 0);

      Common.writeLE64(output, 0, amount);
      Common.copy(output, 8, encodedScript, 0, encodedScript.size());

      return Array.freeze(output);
    };
  };

  // Representation of a Bitcoin transaction.
  public class Transaction(version : Nat32, _txIns : [TxIn],
    _txOuts : [TxOut]) {

    public let txIns = _txIns;
    public let txOuts = _txOuts;

    // Compute the transaction hash.
    public func id() : [Nat8] {
     let doubleHash : [Nat8] = Hash.doubleSHA256(toBytes());
     return Array.tabulate<Nat8>(doubleHash.size(),
       func (n : Nat) {
         doubleHash[doubleHash.size() - 1 - n];
       }
     );
    };

    // Create a signature hash for the given TxIn index.
    // Only SIGHASH_ALL is currently supported.
    // Output layout: | Tx data | SighashType |.
    public func createSignatureHash(scriptPubKey : Script.Script,
      txInIndex : Nat32, sigHashType : Types.SighashType) : [Nat8] {
      assert(sigHashType == Types.SIGHASH_ALL);

      // Clear scripts for other TxIns.
      for (i in Iter.range(0, txIns.size() - 1)) {
        txIns[i].script := [];
      };

      // Set script for current TxIn to given scriptPubKey.
      txIns[Nat32.toNat(txInIndex)].script := scriptPubKey;

      // Serialize transaction and append SighashType.
      let txData =  toBytes();
      let output = Array.init<Nat8>(txData.size() + 4, 0);

      Common.copy(output, 0, txData, 0, txData.size());
      Common.writeLE32(output, txData.size(), sigHashType);

      return Array.freeze(output);
    };

    // Serialize transaction to bytes with layout:
    // | version | len(txIns) | txIns | len(txOuts) | txOuts | locktime |.
    public func toBytes() : [Nat8] {

      // Serialize TxIns to bytes.
      let serializedTxIns : [[Nat8]] = Array.map<TxIn, [Nat8]>(txIns,
        func (txIn) {
          txIn.toBytes();
        });

      // Serialize TxOuts to bytes.
      let serializedTxOuts : [[Nat8]] = Array.map<TxOut, [Nat8]>(txOuts,
        func (txOut) {
          txOut.toBytes();
        });

      // Encodes the sizes of TxIns and TxOuts as varint.
      let serializedTxInSize : [Nat8] = Common.encodeVarint(txIns.size());
      let serializedTxOutSize : [Nat8] = Common.encodeVarint(txOuts.size());

      // Compute total size of all serialized TxIns.
      let totalTxInSize : Nat = Array.foldLeft<[Nat8], Nat>(
        serializedTxIns, 0, func (total : Nat, serializedTxIn : [Nat8]) {
          total + serializedTxIn.size();
        });

      // Compute total size of all serialized TxOuts.
      let totalTxOutSize : Nat = Array.foldLeft<[Nat8], Nat>(
        serializedTxOuts, 0, func (total : Nat, serializedTxOut : [Nat8]) {
          total + serializedTxOut.size();
        });

      // Total size of output is excluding sigHashType.
      let totalSize = 4 + serializedTxInSize.size() + totalTxInSize +
        serializedTxOutSize.size() + totalTxOutSize + 4;
      let output = Array.init<Nat8>(totalSize, 0);
      var outputOffset = 0;

      // Write version
      Common.writeLE32(output, outputOffset, version);
      outputOffset += 4;

      // Write TxIns size.
      Common.copy(output, outputOffset, serializedTxInSize, 0,
        serializedTxInSize.size());
      outputOffset += serializedTxInSize.size();

      // Write serialized TxIns.
      for (serializedTxIn in serializedTxIns.vals()) {
        Common.copy(output, outputOffset, serializedTxIn, 0,
          serializedTxIn.size());
        outputOffset += serializedTxIn.size();
      };

      // Write TxOuts size.
      Common.copy(output, outputOffset, serializedTxOutSize, 0,
        serializedTxOutSize.size());
      outputOffset += serializedTxOutSize.size();

      // Write serialized TxIns.
      for (serializedTxOut in serializedTxOuts.vals()) {
        Common.copy(output, outputOffset, serializedTxOut, 0,
          serializedTxOut.size());
        outputOffset += serializedTxOut.size();
      };

      // Write locktime.
      Common.writeLE32(output, outputOffset, 0);
      outputOffset += 4;

      assert(outputOffset == output.size());
      return Array.freeze(output);
    };
  };
};
