import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseTag,
  encodeTag,
  parseLength,
  encodeLength,
  parse,
  encode,
  type Tlv,
  TagClass,
} from "./index.ts";

describe("Tag parsing", () => {
  it("parses single-byte primitive tag", () => {
    const data = new Uint8Array([0x01]);
    const result = parseTag(data, 0);
    assert.equal(result.tag.number, 0x01);
    assert.equal(result.tag.constructed, false);
    assert.equal(result.tag.class, TagClass.Universal);
    assert.equal(result.bytesRead, 1);
  });

  it("parses single-byte constructed tag", () => {
    const data = new Uint8Array([0x30]); // SEQUENCE
    const result = parseTag(data, 0);
    assert.equal(result.tag.number, 0x10);
    assert.equal(result.tag.constructed, true);
    assert.equal(result.tag.class, TagClass.Universal);
  });

  it("parses context-specific tag", () => {
    const data = new Uint8Array([0x9f, 0x27]); // EMV tag 9F27
    const result = parseTag(data, 0);
    assert.equal(result.tag.number, 0x27);
    assert.equal(result.tag.class, TagClass.ContextSpecific);
    assert.equal(result.bytesRead, 2);
  });

  it("parses three-byte tag", () => {
    const data = new Uint8Array([0x9f, 0x81, 0x02]); // Tag 9F8102
    const result = parseTag(data, 0);
    assert.equal(result.tag.number, 0x82);
    assert.equal(result.bytesRead, 3);
  });

  it("returns raw bytes for tag", () => {
    const data = new Uint8Array([0x9f, 0x27, 0x01, 0x00]);
    const result = parseTag(data, 0);
    assert.deepEqual(result.tag.bytes, new Uint8Array([0x9f, 0x27]));
  });
});

describe("Tag encoding", () => {
  it("encodes single-byte tag", () => {
    const bytes = encodeTag({ number: 0x01, constructed: false, class: TagClass.Universal });
    assert.deepEqual(bytes, new Uint8Array([0x01]));
  });

  it("encodes constructed tag", () => {
    const bytes = encodeTag({ number: 0x10, constructed: true, class: TagClass.Universal });
    assert.deepEqual(bytes, new Uint8Array([0x30]));
  });

  it("encodes multi-byte tag", () => {
    const bytes = encodeTag({ number: 0x27, constructed: false, class: TagClass.ContextSpecific });
    assert.deepEqual(bytes, new Uint8Array([0x9f, 0x27]));
  });

  it("encodes three-byte tag with continuation bits", () => {
    // Tag number 0x82 (130) needs two bytes: 0x81 0x02 (130 = 1*128 + 2)
    const bytes = encodeTag({ number: 0x82, constructed: false, class: TagClass.ContextSpecific });
    assert.deepEqual(bytes, new Uint8Array([0x9f, 0x81, 0x02]));
  });
});

describe("Length parsing", () => {
  it("parses short form length", () => {
    const data = new Uint8Array([0x05]);
    const result = parseLength(data, 0);
    assert.equal(result.length, 5);
    assert.equal(result.bytesRead, 1);
  });

  it("parses zero length", () => {
    const data = new Uint8Array([0x00]);
    const result = parseLength(data, 0);
    assert.equal(result.length, 0);
    assert.equal(result.bytesRead, 1);
  });

  it("parses two-byte long form length", () => {
    const data = new Uint8Array([0x81, 0x80]); // 128
    const result = parseLength(data, 0);
    assert.equal(result.length, 128);
    assert.equal(result.bytesRead, 2);
  });

  it("parses three-byte long form length", () => {
    const data = new Uint8Array([0x82, 0x01, 0x00]); // 256
    const result = parseLength(data, 0);
    assert.equal(result.length, 256);
    assert.equal(result.bytesRead, 3);
  });
});

describe("Length encoding", () => {
  it("encodes short form length", () => {
    const bytes = encodeLength(5);
    assert.deepEqual(bytes, new Uint8Array([0x05]));
  });

  it("encodes length 127 as short form", () => {
    const bytes = encodeLength(127);
    assert.deepEqual(bytes, new Uint8Array([0x7f]));
  });

  it("encodes length 128 as long form", () => {
    const bytes = encodeLength(128);
    assert.deepEqual(bytes, new Uint8Array([0x81, 0x80]));
  });

  it("encodes length 256 as long form", () => {
    const bytes = encodeLength(256);
    assert.deepEqual(bytes, new Uint8Array([0x82, 0x01, 0x00]));
  });
});

describe("TLV parsing", () => {
  it("parses simple primitive TLV", () => {
    const data = new Uint8Array([0x01, 0x02, 0xab, 0xcd]);
    const tlvs = parse(data);
    assert.equal(tlvs.length, 1);
    assert.equal(tlvs[0]!.tag.number, 0x01);
    assert.deepEqual(tlvs[0]!.value, new Uint8Array([0xab, 0xcd]));
  });

  it("parses multiple TLVs", () => {
    const data = new Uint8Array([0x01, 0x01, 0xaa, 0x02, 0x01, 0xbb]);
    const tlvs = parse(data);
    assert.equal(tlvs.length, 2);
    assert.deepEqual(tlvs[0]!.value, new Uint8Array([0xaa]));
    assert.deepEqual(tlvs[1]!.value, new Uint8Array([0xbb]));
  });

  it("parses constructed TLV with children", () => {
    // 30 06 01 01 AA 02 01 BB - SEQUENCE containing two primitives
    const data = new Uint8Array([0x30, 0x06, 0x01, 0x01, 0xaa, 0x02, 0x01, 0xbb]);
    const tlvs = parse(data);
    assert.equal(tlvs.length, 1);
    assert.equal(tlvs[0]!.tag.constructed, true);
    assert.equal(tlvs[0]!.children?.length, 2);
    assert.deepEqual(tlvs[0]!.children?.[0]?.value, new Uint8Array([0xaa]));
  });

  it("parses EMV-style multi-byte tag", () => {
    // 9F27 01 80 - Cryptogram Information Data
    const data = new Uint8Array([0x9f, 0x27, 0x01, 0x80]);
    const tlvs = parse(data);
    assert.equal(tlvs.length, 1);
    assert.deepEqual(tlvs[0]!.tag.bytes, new Uint8Array([0x9f, 0x27]));
  });

  it("parses empty TLV", () => {
    const data = new Uint8Array([0x01, 0x00]);
    const tlvs = parse(data);
    assert.equal(tlvs.length, 1);
    assert.deepEqual(tlvs[0]!.value, new Uint8Array([]));
  });
});

describe("TLV encoding", () => {
  it("encodes simple primitive TLV", () => {
    const tlv: Tlv = {
      tag: { number: 0x01, constructed: false, class: TagClass.Universal },
      value: new Uint8Array([0xab, 0xcd]),
    };
    const bytes = encode([tlv]);
    assert.deepEqual(bytes, new Uint8Array([0x01, 0x02, 0xab, 0xcd]));
  });

  it("encodes multiple TLVs", () => {
    const tlvs: Tlv[] = [
      { tag: { number: 0x01, constructed: false, class: TagClass.Universal }, value: new Uint8Array([0xaa]) },
      { tag: { number: 0x02, constructed: false, class: TagClass.Universal }, value: new Uint8Array([0xbb]) },
    ];
    const bytes = encode(tlvs);
    assert.deepEqual(bytes, new Uint8Array([0x01, 0x01, 0xaa, 0x02, 0x01, 0xbb]));
  });

  it("encodes constructed TLV with children", () => {
    const tlv: Tlv = {
      tag: { number: 0x10, constructed: true, class: TagClass.Universal },
      value: new Uint8Array(),
      children: [
        { tag: { number: 0x01, constructed: false, class: TagClass.Universal }, value: new Uint8Array([0xaa]) },
        { tag: { number: 0x02, constructed: false, class: TagClass.Universal }, value: new Uint8Array([0xbb]) },
      ],
    };
    const bytes = encode([tlv]);
    assert.deepEqual(bytes, new Uint8Array([0x30, 0x06, 0x01, 0x01, 0xaa, 0x02, 0x01, 0xbb]));
  });
});

describe("Roundtrip encoding/decoding", () => {
  it("roundtrips complex nested structure", () => {
    const original = new Uint8Array([
      0x30, 0x0c,
        0x01, 0x01, 0xaa,
        0x30, 0x07,
          0x02, 0x02, 0xbb, 0xcc,
          0x03, 0x01, 0xdd,
    ]);
    const parsed = parse(original);
    const encoded = encode(parsed);
    assert.deepEqual(encoded, original);
  });
});

describe("Error handling", () => {
  describe("parseTag errors", () => {
    it("throws when no data at offset", () => {
      const data = new Uint8Array([]);
      assert.throws(() => parseTag(data, 0), { message: "No data at offset 0" });
    });

    it("throws when offset is beyond data", () => {
      const data = new Uint8Array([0x01]);
      assert.throws(() => parseTag(data, 5), { message: "No data at offset 5" });
    });

    it("throws for truncated multi-byte tag", () => {
      // 0x1F indicates multi-byte tag, but no subsequent bytes
      const data = new Uint8Array([0x1f]);
      assert.throws(() => parseTag(data, 0), { message: "Unexpected end of data while parsing multi-byte tag" });
    });

    it("throws for incomplete multi-byte tag continuation", () => {
      // 0x9F starts multi-byte, 0x81 has continuation bit set but no following byte
      const data = new Uint8Array([0x9f, 0x81]);
      assert.throws(() => parseTag(data, 0), { message: "Unexpected end of data while parsing multi-byte tag" });
    });
  });

  describe("parseLength errors", () => {
    it("throws when no data at offset", () => {
      const data = new Uint8Array([]);
      assert.throws(() => parseLength(data, 0), { message: "No data at offset 0" });
    });

    it("throws for indefinite length encoding", () => {
      // 0x80 means indefinite length (not supported)
      const data = new Uint8Array([0x80]);
      assert.throws(() => parseLength(data, 0), { message: "Indefinite length not supported" });
    });

    it("throws for truncated long form length", () => {
      // 0x82 means 2 length bytes follow, but only 1 provided
      const data = new Uint8Array([0x82, 0x01]);
      assert.throws(() => parseLength(data, 0), { message: "Unexpected end of data while parsing length" });
    });

    it("throws for missing long form length bytes", () => {
      // 0x81 means 1 length byte follows, but none provided
      const data = new Uint8Array([0x81]);
      assert.throws(() => parseLength(data, 0), { message: "Unexpected end of data while parsing length" });
    });
  });

  describe("encodeLength errors", () => {
    it("throws for negative length", () => {
      assert.throws(() => encodeLength(-1), { message: "Length cannot be negative" });
    });

    it("throws for negative length -100", () => {
      assert.throws(() => encodeLength(-100), { message: "Length cannot be negative" });
    });
  });
});
