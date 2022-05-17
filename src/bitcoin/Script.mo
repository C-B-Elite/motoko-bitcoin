import Buffer "mo:base/Buffer";
import Nat8 "mo:base/Nat8";
import Array "mo:base/Array";
import Common "../Common";

module Script {
  // Supported set of opcodes.
  public type Opcode = {
    #OP_DUP;
    #OP_HASH160;
    #OP_EQUALVERIFY;
    #OP_CHECKSIG;
  };

  // An instruction is either an opcode or data.
  public type Instruction = {
    #opcode : Opcode;
    #data : [Nat8];
  };

  // A script is an array of instructions.
  public type Script = [Instruction];

  // Convert given opcode to its byte representation.
  func encodeOpcode(opcode : Opcode) : Nat8 {
    return switch (opcode) {
      case (#OP_DUP) {
        0x76;
      };
      case (#OP_EQUALVERIFY) {
        0x88;
      };
      case (#OP_HASH160) {
        0xa9;
      };
      case (#OP_CHECKSIG) {
        0xac;
      };
    };
  };

  // Serialize given script to bytes.
  public func toBytes(script : Script) : [Nat8] {
    let buf : Buffer.Buffer<Nat8> = Buffer.Buffer<Nat8>(script.size());

    for (instruction in script.vals()) {
      switch (instruction) {
        case (#opcode(opcode)) {
          buf.add(encodeOpcode(opcode));
        };
        case (#data data) {
          // Max data size currently supported.
          assert(data.size() < 0x4b);

          // Add data size.
          buf.add(Nat8.fromIntWrap(data.size()));

          // Copy data into buffer.
          for (item in data.vals()) {
            buf.add(item);
          };
        };
      };
    };

    // Prepend buffer size as varint and return.
    let encodedBufSize = Common.encodeVarint(buf.size());
    return Array.tabulate<Nat8>(encodedBufSize.size() + buf.size(),
      func (i) {
        if (i < encodedBufSize.size()) {
          encodedBufSize[i];
        } else {
          buf.get(i - encodedBufSize.size());
        };
      });
  };
};
