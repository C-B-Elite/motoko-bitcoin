import Transaction "../../src/bitcoin/Transaction";
import Script "../../src/bitcoin/Script";
import P2pkh "../../src/bitcoin/P2pkh";
import Types "../../src/bitcoin/Types";
import BitcoinTestTools "./bitcoinTestTools";
import Blob "mo:base/Blob";
import Debug "mo:base/Debug";

let TxIn = Transaction.TxIn;
let TxOut = Transaction.TxOut;
let Account = BitcoinTestTools.Account;
let ecdsaSign = BitcoinTestTools.ecdsaSign;
let signatureToDer = BitcoinTestTools.signatureToDer;

let wallet = {
  account1 = Account(22265090479312778178772228083027296664144);
  account2 = Account(29595381593786747354608258168471648998894101022644411052850960746671046944116);
  account3 = Account(29595381593786747354608258168471648998894101022644411057647114205835530364276);
};

do {
  // Create Transaction inputs.
  let txIn1 = TxIn({
    txid = Blob.fromArray([
      0x24, 0x5e, 0x2d, 0x1f, 0x87, 0x41, 0x58, 0x36, 0xcb, 0xb7,
      0xb0, 0xbc, 0x84, 0xe4, 0x0f, 0x4c, 0xa1, 0xd2, 0xa8, 0x12,
      0xbe, 0x0e, 0xda, 0x38, 0x1f, 0x02, 0xfb, 0x22, 0x24, 0xb4,
      0xad, 0x69]);
    vout = 0
  }, 0xffffffff);

  let txIn2 = TxIn({
    txid = Blob.fromArray([
      0x24, 0x5e, 0x2d, 0x1f, 0x87, 0x41, 0x58, 0x36, 0xcb, 0xb7,
      0xb0, 0xbc, 0x84, 0xe4, 0x0f, 0x4c, 0xa1, 0xd2, 0xa8, 0x12,
      0xbe, 0x0e, 0xda, 0x38, 0x1f, 0x02, 0xfb, 0x22, 0x24, 0xb4,
      0xad, 0x69]);
    vout = 1
  }, 0xffffffff);

  let (script1, script2, script3) = switch (
    P2pkh.makeScript(wallet.account1.p2pkhAddress),
    P2pkh.makeScript(wallet.account2.p2pkhAddress),
    P2pkh.makeScript(wallet.account3.p2pkhAddress)
  ) {
    case (#ok script1, #ok script2, #ok script3) {
      (script1, script2, script3)
    };
    case _ {
      Debug.trap("Failed to make p2pkh scripts");
    };
  };

  // Create Transaction outputs.
  let txOut = TxOut(
    95000,
    script3
  );

  // Create transaction from inputs and outputs.
  let tx = Transaction.Transaction(1, [txIn1, txIn2], [txOut]);

  // Create sighashes for the different TxIns.
  let sighash0 = tx.createSignatureHash(script2, 0, Types.SIGHASH_ALL);
  let sighash1 = tx.createSignatureHash(script1, 1, Types.SIGHASH_ALL);

  // Sign the sighashes.
  let sig0 = ecdsaSign(
    wallet.account2.sk,
    112609188155181958867411722703297103910455907901682906025087121180755153638506,
    sighash0
    );
  let sig1 = ecdsaSign(
    wallet.account1.sk,
    83488564957391661447598237273307748460904361497263649543725348730424228953185,
    sighash1
  );

  // Encode signatures to Der.
  let sig0Encoded = signatureToDer(sig0, Types.SIGHASH_ALL);
  let sig1Encoded = signatureToDer(sig1, Types.SIGHASH_ALL);

  // Create unlocking scripts and plug them to their associated TxIns.
  let scriptSig0 : Script.Script = [#data(sig0Encoded), #data(wallet.account2.pkData)];
  let scriptSig1 = [#data(sig1Encoded), #data(wallet.account1.pkData)];
  tx.txIns[1].script := scriptSig1;
  tx.txIns[0].script := scriptSig0;

  assert(tx.id() == [
    0x36, 0x1f, 0xbb, 0x9d, 0xe4, 0xef, 0x5b, 0xfa, 0x8c, 0x1c, 0xbd, 0x5e,
    0xff, 0x81, 0x8e, 0xd9, 0x27, 0x3f, 0x6e, 0x1f, 0x74, 0xb4, 0x1a, 0x7f,
    0x9a, 0x9e, 0x84, 0x27, 0xc9, 0x00, 0x8b, 0x93
  ]);
};
