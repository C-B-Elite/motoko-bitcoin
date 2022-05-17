module {
   // A single unit of Bitcoin.
  public type Satoshi = Nat64;

  // The type of Bitcoin network.
  public type Network = {
    #Bitcoin;
    #Regtest;
    #Testnet;
    #Signet;
  };

  // A reference to a transaction output.
  public type OutPoint = {
    txid : Blob;
    vout : Nat32;
  };

  // An unspent transaction output.
  public type Utxo = {
    outpoint : OutPoint;
    value : Satoshi;
    height : Nat32;
    confirmations : Nat32;
  };

  public type SighashType = Nat32;
  public let SIGHASH_ALL : SighashType = 0x01;

  public type P2PkhAddress = Text;
};
