# ber-tlv

A modern TypeScript library for ASN.1 BER-TLV encoding and decoding.

## Features

- Parse BER-TLV encoded data into structured objects
- Encode TLV structures back to binary format
- Support for multi-byte tags (up to 3 bytes)
- Support for short and long form length encoding
- Handle nested/constructed TLV structures
- Zero runtime dependencies
- 100% test coverage

## Installation

```bash
npm install ber-tlv
```

## Usage

### Parsing TLV Data

```typescript
import { parse } from "ber-tlv";

// Parse a simple TLV: tag 0x01, length 0x02, value 0xABCD
const data = new Uint8Array([0x01, 0x02, 0xab, 0xcd]);
const tlvs = parse(data);

console.log(tlvs[0].tag.number);  // 1
console.log(tlvs[0].value);       // Uint8Array [0xab, 0xcd]
```

### Parsing Nested Structures

```typescript
import { parse } from "ber-tlv";

// SEQUENCE containing two primitives
const data = new Uint8Array([0x30, 0x06, 0x01, 0x01, 0xaa, 0x02, 0x01, 0xbb]);
const tlvs = parse(data);

console.log(tlvs[0].tag.constructed);    // true
console.log(tlvs[0].children?.length);   // 2
console.log(tlvs[0].children?.[0].value); // Uint8Array [0xaa]
```

### Parsing EMV-Style Multi-Byte Tags

```typescript
import { parse } from "ber-tlv";

// EMV tag 9F27 (Cryptogram Information Data)
const data = new Uint8Array([0x9f, 0x27, 0x01, 0x80]);
const tlvs = parse(data);

console.log(tlvs[0].tag.bytes);  // Uint8Array [0x9f, 0x27]
console.log(tlvs[0].tag.number); // 39 (0x27)
```

### Encoding TLV Data

```typescript
import { encode, TagClass, type Tlv } from "ber-tlv";

const tlv: Tlv = {
  tag: { number: 0x01, constructed: false, class: TagClass.Universal },
  value: new Uint8Array([0xab, 0xcd]),
};

const encoded = encode([tlv]);
console.log(encoded); // Uint8Array [0x01, 0x02, 0xab, 0xcd]
```

### Encoding Nested Structures

```typescript
import { encode, TagClass, type Tlv } from "ber-tlv";

const tlv: Tlv = {
  tag: { number: 0x10, constructed: true, class: TagClass.Universal },
  value: new Uint8Array(),
  children: [
    { tag: { number: 0x01, constructed: false, class: TagClass.Universal }, value: new Uint8Array([0xaa]) },
    { tag: { number: 0x02, constructed: false, class: TagClass.Universal }, value: new Uint8Array([0xbb]) },
  ],
};

const encoded = encode([tlv]);
// Uint8Array [0x30, 0x06, 0x01, 0x01, 0xaa, 0x02, 0x01, 0xbb]
```

### Low-Level Tag/Length Functions

```typescript
import { parseTag, encodeTag, parseLength, encodeLength, TagClass } from "ber-tlv";

// Parse a tag
const tagResult = parseTag(new Uint8Array([0x9f, 0x27]), 0);
console.log(tagResult.tag.number);    // 39
console.log(tagResult.bytesRead);     // 2

// Encode a tag
const tagBytes = encodeTag({ number: 0x27, constructed: false, class: TagClass.ContextSpecific });
console.log(tagBytes); // Uint8Array [0x9f, 0x27]

// Parse a length
const lengthResult = parseLength(new Uint8Array([0x82, 0x01, 0x00]), 0);
console.log(lengthResult.length);     // 256
console.log(lengthResult.bytesRead);  // 3

// Encode a length
const lengthBytes = encodeLength(256);
console.log(lengthBytes); // Uint8Array [0x82, 0x01, 0x00]
```

## API Reference

### Types

#### `TagClass`
```typescript
const TagClass = {
  Universal: 0b00,
  Application: 0b01,
  ContextSpecific: 0b10,
  Private: 0b11,
} as const;
```

#### `Tag`
```typescript
interface Tag {
  readonly number: number;        // Decoded tag number
  readonly constructed: boolean;  // true for container tags
  readonly class: TagClass;       // Tag class
  readonly bytes?: Uint8Array;    // Raw tag bytes
}
```

#### `Tlv`
```typescript
interface Tlv {
  readonly tag: Tag;
  readonly value: Uint8Array;           // Value bytes
  readonly children?: readonly Tlv[];   // Child elements for constructed tags
}
```

### Functions

| Function | Description |
|----------|-------------|
| `parse(data: Uint8Array): Tlv[]` | Parse BER-TLV data into TLV structures |
| `encode(tlvs: readonly Tlv[]): Uint8Array` | Encode TLV structures to BER-TLV bytes |
| `parseTag(data: Uint8Array, offset: number): ParseTagResult` | Parse a single tag |
| `encodeTag(tag: Omit<Tag, "bytes">): Uint8Array` | Encode a tag to bytes |
| `parseLength(data: Uint8Array, offset: number): ParseLengthResult` | Parse a length field |
| `encodeLength(length: number): Uint8Array` | Encode a length to bytes |

## BER-TLV Format

This library implements BER-TLV encoding as defined in ISO/IEC 8825-1 / X.690.

### Tag Structure
- **Single-byte tag**: Class (2 bits) | Constructed (1 bit) | Tag number (5 bits)
- **Multi-byte tag**: First byte has tag number = 0x1F, subsequent bytes use bit 7 as continuation flag

### Length Encoding
- **Short form** (0-127): Single byte, bit 7 = 0
- **Long form** (128+): First byte = 0x80 | number of length bytes, followed by length bytes

## Requirements

- Node.js 22+
- TypeScript 5.7+

## License

MIT
