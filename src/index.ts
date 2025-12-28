/**
 * ASN.1 BER-TLV encoding/decoding library
 * Implements ISO/IEC 8825-1 / X.690 BER encoding rules for TLV structures
 */

/** Tag class as defined in ASN.1 */
export const TagClass = {
  Universal: 0b00,
  Application: 0b01,
  ContextSpecific: 0b10,
  Private: 0b11,
} as const;

export type TagClass = (typeof TagClass)[keyof typeof TagClass];

/** Parsed tag information */
export interface Tag {
  /** Tag number (decoded from potentially multi-byte representation) */
  readonly number: number;
  /** Whether this is a constructed (container) tag */
  readonly constructed: boolean;
  /** Tag class (Universal, Application, ContextSpecific, Private) */
  readonly class: TagClass;
  /** Raw tag bytes as they appear in the encoded data */
  readonly bytes?: Uint8Array;
}

/** TLV structure */
export interface Tlv {
  /** Tag information */
  readonly tag: Tag;
  /** Value bytes (empty for constructed tags with children) */
  readonly value: Uint8Array;
  /** Child TLV elements for constructed tags */
  readonly children?: readonly Tlv[];
}

/** Result of parsing a tag */
export interface ParseTagResult {
  readonly tag: Tag;
  readonly bytesRead: number;
}

/** Result of parsing a length */
export interface ParseLengthResult {
  readonly length: number;
  readonly bytesRead: number;
}

/**
 * Parse a BER-TLV tag from the given data at the specified offset
 */
export function parseTag(data: Uint8Array, offset: number): ParseTagResult {
  const firstByte = data[offset];
  if (firstByte === undefined) {
    throw new Error(`No data at offset ${offset}`);
  }

  const tagClass = ((firstByte >> 6) & 0b11) as TagClass;
  const constructed = (firstByte & 0b00100000) !== 0;
  const tagNumberPart = firstByte & 0b00011111;

  // Single-byte tag
  if (tagNumberPart !== 0b11111) {
    return {
      tag: {
        number: tagNumberPart,
        constructed,
        class: tagClass,
        bytes: new Uint8Array([firstByte]),
      },
      bytesRead: 1,
    };
  }

  // Multi-byte tag: subsequent bytes have bit 7 as continuation flag
  let tagNumber = 0;
  let i = offset + 1;
  const tagBytes: number[] = [firstByte];

  while (i < data.length) {
    const byte = data[i];
    if (byte === undefined) {
      throw new Error(`Unexpected end of data while parsing multi-byte tag`);
    }
    tagBytes.push(byte);
    tagNumber = (tagNumber << 7) | (byte & 0x7f);
    i++;
    if ((byte & 0x80) === 0) {
      break;
    }
  }

  return {
    tag: {
      number: tagNumber,
      constructed,
      class: tagClass,
      bytes: new Uint8Array(tagBytes),
    },
    bytesRead: tagBytes.length,
  };
}

/**
 * Encode a tag to BER-TLV bytes
 */
export function encodeTag(tag: Omit<Tag, "bytes">): Uint8Array {
  const classBits = (tag.class << 6) & 0b11000000;
  const constructedBit = tag.constructed ? 0b00100000 : 0;

  // Single-byte tag (tag number fits in 5 bits, i.e., 0-30)
  if (tag.number <= 30) {
    return new Uint8Array([classBits | constructedBit | tag.number]);
  }

  // Multi-byte tag
  const bytes: number[] = [classBits | constructedBit | 0b11111];

  // Encode tag number in base-128 with continuation bits
  const tagNumberBytes: number[] = [];
  let remaining = tag.number;
  while (remaining > 0) {
    tagNumberBytes.unshift(remaining & 0x7f);
    remaining >>= 7;
  }

  // Set continuation bit on all but the last byte
  for (let i = 0; i < tagNumberBytes.length - 1; i++) {
    tagNumberBytes[i]! |= 0x80;
  }

  bytes.push(...tagNumberBytes);
  return new Uint8Array(bytes);
}

/**
 * Parse a BER-TLV length from the given data at the specified offset
 */
export function parseLength(data: Uint8Array, offset: number): ParseLengthResult {
  const firstByte = data[offset];
  if (firstByte === undefined) {
    throw new Error(`No data at offset ${offset}`);
  }

  // Short form: bit 7 is 0, bits 6-0 are the length
  if ((firstByte & 0x80) === 0) {
    return { length: firstByte, bytesRead: 1 };
  }

  // Long form: bit 7 is 1, bits 6-0 are the number of subsequent length bytes
  const numLengthBytes = firstByte & 0x7f;

  if (numLengthBytes === 0) {
    throw new Error("Indefinite length not supported");
  }

  let length = 0;
  for (let i = 0; i < numLengthBytes; i++) {
    const byte = data[offset + 1 + i];
    if (byte === undefined) {
      throw new Error(`Unexpected end of data while parsing length`);
    }
    length = (length << 8) | byte;
  }

  return { length, bytesRead: 1 + numLengthBytes };
}

/**
 * Encode a length to BER-TLV bytes
 */
export function encodeLength(length: number): Uint8Array {
  if (length < 0) {
    throw new Error("Length cannot be negative");
  }

  // Short form: lengths 0-127
  if (length <= 127) {
    return new Uint8Array([length]);
  }

  // Long form: determine number of bytes needed
  const lengthBytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    lengthBytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }

  return new Uint8Array([0x80 | lengthBytes.length, ...lengthBytes]);
}

/**
 * Parse BER-TLV encoded data into TLV structures
 */
export function parse(data: Uint8Array): Tlv[] {
  const tlvs: Tlv[] = [];
  let offset = 0;

  while (offset < data.length) {
    const { tag, bytesRead: tagBytesRead } = parseTag(data, offset);
    offset += tagBytesRead;

    const { length, bytesRead: lengthBytesRead } = parseLength(data, offset);
    offset += lengthBytesRead;

    const value = data.slice(offset, offset + length);
    offset += length;

    if (tag.constructed) {
      const children = parse(value);
      tlvs.push({ tag, value: new Uint8Array(), children });
    } else {
      tlvs.push({ tag, value });
    }
  }

  return tlvs;
}

/**
 * Encode TLV structures to BER-TLV bytes
 */
export function encode(tlvs: readonly Tlv[]): Uint8Array {
  const chunks: Uint8Array[] = [];

  for (const tlv of tlvs) {
    const tagBytes = tlv.tag.bytes ?? encodeTag(tlv.tag);

    let valueBytes: Uint8Array;
    if (tlv.tag.constructed && tlv.children && tlv.children.length > 0) {
      valueBytes = encode(tlv.children);
    } else {
      valueBytes = tlv.value;
    }

    const lengthBytes = encodeLength(valueBytes.length);

    chunks.push(tagBytes, lengthBytes, valueBytes);
  }

  // Concatenate all chunks
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}
