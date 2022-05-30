import Nat8 "mo:base/Nat8";
import Nat16 "mo:base/Nat16";
import Nat32 "mo:base/Nat32";
import Nat64 "mo:base/Nat64";
import Iter "mo:base/Iter";
import Array "mo:base/Array";
import Common "./Common";

module {
  public let maxNat8 : Nat = 0xff;
  public let maxNat16 : Nat = 0xffff;
  public let maxNat32 : Nat = 0xffffffff;
  public let maxNat64 : Nat = 0xffffffffffffffff;
  let varintNat16Flag : Nat8 = 0xfd;
  let varintNat32Flag : Nat8 = 0xfe;
  let varintNat64Flag : Nat8 = 0xff;

  // Read a number of elements from the given iterator and return as array. If
  // reverse is true, will read return the elements in reverse order.
  // Returns null if the iterator does not produce enough data.
  public func read(data : Iter.Iter<Nat8>, count : Nat,
    reverse : Bool) : ?[Nat8] {
    return do ? {
      let readData : [var Nat8] = Array.init<Nat8>(count, 0);
      if (reverse) {
        var nextReadIndex : Nat = count - 1;

        label Loop loop {
          readData[nextReadIndex] := data.next()!;
          if (nextReadIndex == 0) {
            break Loop;
          };
          nextReadIndex -= 1;
        };
      } else {
        var nextReadIndex : Nat = 0;

        while (nextReadIndex < count) {
          readData[nextReadIndex] := data.next()!;
          nextReadIndex += 1;
        };
      };

      Array.freeze(readData);
    };
  };

  // Read little endian 16-bit natural number starting at offset.
  // Returns null if the iterator does not produce enough data.
  public func readLE16(data : Iter.Iter<Nat8>) : ?Nat16 {
    return (do ? {
      let (a, b) = (data.next()!, data.next()!);
      Nat16.fromIntWrap(Nat8.toNat(b)) << 8 |
      Nat16.fromIntWrap(Nat8.toNat(a));
    });
  };

  // Read little endian 32-bit natural number starting at offset.
  // Returns null if the iterator does not produce enough data.
  public func readLE32(data : Iter.Iter<Nat8>) : ?Nat32 {
    return (do ? {
      let (a, b ,c ,d) =
        (data.next()!, data.next()!, data.next()!, data.next()!);
      Nat32.fromIntWrap(Nat8.toNat(d)) << 24 |
      Nat32.fromIntWrap(Nat8.toNat(c)) << 16 |
      Nat32.fromIntWrap(Nat8.toNat(b)) << 8 |
      Nat32.fromIntWrap(Nat8.toNat(a));
    });
  };

  // Read little endian 64-bit natural number starting at offset.
  // Returns null if the iterator does not produce enough data.
  public func readLE64(data : Iter.Iter<Nat8>) : ?Nat64 {
    return (do ? {
      let (a, b, c, d, e, f, g, h) = (
        data.next()!, data.next()!, data.next()!, data.next()!,
        data.next()!, data.next()!, data.next()!, data.next()!
      );

      Nat64.fromIntWrap(Nat8.toNat(h)) << 56 |
      Nat64.fromIntWrap(Nat8.toNat(g)) << 48 |
      Nat64.fromIntWrap(Nat8.toNat(f)) << 40 |
      Nat64.fromIntWrap(Nat8.toNat(e)) << 32 |
      Nat64.fromIntWrap(Nat8.toNat(d)) << 24 |
      Nat64.fromIntWrap(Nat8.toNat(c)) << 16 |
      Nat64.fromIntWrap(Nat8.toNat(b)) << 8 |
      Nat64.fromIntWrap(Nat8.toNat(a));
    });
  };

  // Read one element from the given iterator.
  // Returns null if the iterator does not produce enough data.
  public func readOne(data : Iter.Iter<Nat8>) : ?Nat8 {
    return data.next();
  };

  // Read and return a varint encoded integer from data.
  // Returns null if the iterator does not produce enough data.
  public func readVarint(data : Iter.Iter<Nat8>) : ?Nat {
    return (do ? {
      let flag : Nat8 = readOne(data)!;
      if (flag == varintNat16Flag) {
        Nat16.toNat(readLE16(data)!)
      } else if (flag == varintNat32Flag) {
        Nat32.toNat(readLE32(data)!)
      } else if (flag == varintNat64Flag) {
        Nat64.toNat(readLE64(data)!)
      } else {
        Nat8.toNat(flag)
      };
    });
  };

  // Encode value as varint.
  public func writeVarint(value : Nat) : [Nat8] {
    assert(value <= maxNat64);

    return if (value < Nat8.toNat(varintNat16Flag)) {
      // Output the value without flags.
      [Nat8.fromIntWrap(value)]
    } else if (value <= maxNat16) {
      // Output Nat16 flag + serialized 2 bytes.
      let result = Array.init<Nat8>(3, varintNat16Flag);
      Common.writeLE16(result, 1, Nat16.fromIntWrap(value));
      Array.freeze(result)
    } else if (value <= maxNat32) {
      // Output Nat32 flag + serialized 4 bytes.
      let result = Array.init<Nat8>(5, varintNat32Flag);
      Common.writeLE32(result, 1, Nat32.fromIntWrap(value));
      Array.freeze(result)
    } else {
      // Output Nat64 flag + serialized 8 bytes.
      let result = Array.init<Nat8>(9, varintNat64Flag);
      Common.writeLE64(result, 1, Nat64.fromIntWrap(value));
      Array.freeze(result)
    };
  };
};
