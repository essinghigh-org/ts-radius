import dgram from "dgram";
import crypto from "crypto";
import type {
  Logger,
  ParsedRadiusAttribute,
  RadiusAccountingAttribute,
  RadiusAccountingRequest,
  RadiusAccountingStatusType,
  RadiusProtocolOptions,
  RadiusResult
} from "./types";
import { decodeAttribute } from "./helpers";

const ACCOUNTING_STATUS_VALUES: Record<RadiusAccountingStatusType, number> = {
  Start: 1,
  Stop: 2,
  "Interim-Update": 3
};

function isUint32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function encodeRadiusAttribute(type: number, value: Buffer): Buffer {
  if (!Number.isInteger(type) || type < 1 || type > 255) {
    throw new Error(`[radius] Invalid attribute type: ${String(type)}`);
  }

  if (value.length > 253) {
    throw new Error(`[radius] Attribute ${String(type)} value too large`);
  }

  return Buffer.concat([Buffer.from([type, value.length + 2]), value]);
}

function encodeStringAttribute(type: number, value: string): Buffer {
  return encodeRadiusAttribute(type, Buffer.from(value, "utf8"));
}

function encodeIntegerAttribute(type: number, value: number): Buffer {
  if (!isUint32(value)) {
    throw new Error(`[radius] Attribute ${String(type)} must be uint32`);
  }

  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value, 0);
  return encodeRadiusAttribute(type, buffer);
}

function encodeAccountingCustomAttribute(attribute: RadiusAccountingAttribute): Buffer {
  if (typeof attribute.value === "string") {
    return encodeStringAttribute(attribute.type, attribute.value);
  }

  if (typeof attribute.value === "number") {
    return encodeIntegerAttribute(attribute.type, attribute.value);
  }

  return encodeRadiusAttribute(attribute.type, attribute.value);
}

function parseAttributes(packet: Buffer, logger?: Logger): ParsedRadiusAttribute[] {
  const attributes: ParsedRadiusAttribute[] = [];
  let offset = 20;

  while (offset + 2 <= packet.length) {
    const t = packet.readUInt8(offset);
    const l = packet.readUInt8(offset + 1);

    if (l < 2) {
      if (logger) logger.warn("[radius] invalid attribute length < 2; stopping parse");
      break;
    }

    if (offset + l > packet.length) {
      if (logger) logger.warn("[radius] attribute length runs past packet end; stopping parse");
      break;
    }

    const value = packet.subarray(offset + 2, offset + l);
    try {
      attributes.push(decodeAttribute(t, value));
    } catch (error: unknown) {
      if (logger) logger.warn("[radius] error decoding attribute", { type: t, error });
    }

    offset += l;
  }

  return attributes;
}

function validateResponsePacket(response: Buffer, logger?: Logger): string | undefined {
  if (response.length < 20) {
    if (logger) logger.warn("[radius] received malformed response (too short)");
    return "malformed_response";
  }

  const declaredLength = response.readUInt16BE(2);
  if (declaredLength !== response.length) {
    if (logger) {
      logger.warn("[radius] received malformed response (length mismatch)", {
        declaredLength,
        actualLength: response.length
      });
    }
    return "malformed_response";
  }

  return undefined;
}

function hasValidResponseAuthenticator(response: Buffer, requestAuthenticator: Buffer, secret: string): boolean {
  const responseAuthenticator = response.subarray(4, 20);
  const hashInput = Buffer.concat([
    Buffer.from([response.readUInt8(0)]),
    Buffer.from([response.readUInt8(1)]),
    response.subarray(2, 4),
    requestAuthenticator,
    response.subarray(20),
    Buffer.from(secret, "utf8")
  ]);
  const expectedAuthenticator = crypto.createHash("md5").update(hashInput).digest();
  return expectedAuthenticator.equals(responseAuthenticator);
}

function validateAccountingRequest(request: RadiusAccountingRequest): void {
  if (!request.username || request.username.trim().length === 0) {
    throw new Error("[radius] accounting request.username is required");
  }

  if (!request.sessionId || request.sessionId.trim().length === 0) {
    throw new Error("[radius] accounting request.sessionId is required");
  }

  const integerFields: Array<[string, number | undefined]> = [
    ["sessionTime", request.sessionTime],
    ["inputOctets", request.inputOctets],
    ["outputOctets", request.outputOctets],
    ["inputPackets", request.inputPackets],
    ["outputPackets", request.outputPackets],
    ["delayTime", request.delayTime],
    ["terminateCause", request.terminateCause]
  ];

  for (const [fieldName, fieldValue] of integerFields) {
    if (fieldValue !== undefined && !isUint32(fieldValue)) {
      throw new Error(`[radius] accounting request.${fieldName} must be uint32`);
    }
  }

  for (const attribute of request.attributes ?? []) {
    if (typeof attribute.value === "number" && !isUint32(attribute.value)) {
      throw new Error(`[radius] accounting attribute ${String(attribute.type)} number values must be uint32`);
    }
  }
}

function buildAccountingAttributes(request: RadiusAccountingRequest): Buffer[] {
  const attrs: Buffer[] = [
    encodeStringAttribute(1, request.username),
    encodeIntegerAttribute(40, ACCOUNTING_STATUS_VALUES[request.statusType]),
    encodeStringAttribute(44, request.sessionId)
  ];

  if (request.delayTime !== undefined) {
    attrs.push(encodeIntegerAttribute(41, request.delayTime));
  }
  if (request.inputOctets !== undefined) {
    attrs.push(encodeIntegerAttribute(42, request.inputOctets));
  }
  if (request.outputOctets !== undefined) {
    attrs.push(encodeIntegerAttribute(43, request.outputOctets));
  }
  if (request.sessionTime !== undefined) {
    attrs.push(encodeIntegerAttribute(46, request.sessionTime));
  }
  if (request.inputPackets !== undefined) {
    attrs.push(encodeIntegerAttribute(47, request.inputPackets));
  }
  if (request.outputPackets !== undefined) {
    attrs.push(encodeIntegerAttribute(48, request.outputPackets));
  }
  if (request.terminateCause !== undefined) {
    attrs.push(encodeIntegerAttribute(49, request.terminateCause));
  }

  for (const attribute of request.attributes ?? []) {
    attrs.push(encodeAccountingCustomAttribute(attribute));
  }

  return attrs;
}

// Minimal RADIUS client using UDP for Access-Request/Accept exchange.
// This is intentionally small and supports only PAP (User-Password) and Class attribute extraction.

export async function radiusAuthenticate(
  host: string,
  username: string,
  password: string,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusResult> {
  const secret = options.secret;
  if (!secret) {
    throw new Error('RADIUS secret is required and cannot be empty');
  }
  const port = options.port || 1812;
  const timeoutMs = options.timeoutMs || 5000;

  if (logger) logger.debug('[radius] authenticate start', { host, user: username });

  return new Promise((resolve, reject) => {
    const client = dgram.createSocket("udp4");
    const id = crypto.randomBytes(1).readUInt8(0);
    const authenticator = crypto.randomBytes(16);

    const attrs: Buffer[] = [];

    // User-Name (type 1)
    const userBuf = Buffer.from(username, "utf8");
    attrs.push(Buffer.concat([Buffer.from([1, userBuf.length + 2]), userBuf]));

    // User-Password (type 2) - PAP per RFC2865 with proper 16-byte block chaining
    const pwdBuf = Buffer.from(password, "utf8");
    const blockCount = Math.ceil(pwdBuf.length / 16) || 1;
    const padded = Buffer.alloc(blockCount * 16, 0);
    pwdBuf.copy(padded);
    const xored = Buffer.alloc(padded.length);
    // For each 16-byte block, MD5(secret + previous) where previous is authenticator for block 0,
    // and the previous encrypted block for subsequent blocks (RFC2865 section 5.2).
    let prev = authenticator;
    for (let b = 0; b < blockCount; b++) {
      const md5 = crypto.createHash("md5").update(Buffer.concat([Buffer.from(secret, "utf8"), prev])).digest();
      for (let i = 0; i < 16; i++) {
        const blockOffset = b * 16 + i;
        const xorByte = padded.readUInt8(blockOffset) ^ md5.readUInt8(i);
        xored.writeUInt8(xorByte, blockOffset);
      }
      prev = xored.subarray(b * 16, b * 16 + 16);
    }
    attrs.push(Buffer.concat([Buffer.from([2, xored.length + 2]), xored]));

    // NAS-IP-Address (type 4) - optional, set to 127.0.0.1
    const nasIp = Buffer.from([127, 0, 0, 1]);
    attrs.push(Buffer.concat([Buffer.from([4, 6]), nasIp]));
    // NAS-Port (type 5) - set to zero by default
    attrs.push(Buffer.concat([Buffer.from([5, 6]), Buffer.from([0, 0, 0, 0])]));
    // Message-Authenticator (type 80) - placeholder 16 bytes (some servers require it)
    attrs.push(Buffer.concat([Buffer.from([80, 18]), Buffer.alloc(16, 0)]));

    const attrBuf = Buffer.concat(attrs);

    const len = 20 + attrBuf.length;
    const header = Buffer.alloc(20);
    header.writeUInt8(1, 0); // Access-Request
    header.writeUInt8(id, 1);
    header.writeUInt16BE(len, 2);
    authenticator.copy(header, 4);

    const packet = Buffer.concat([header, attrBuf]);

    const timer = setTimeout(() => {
      client.close();
      resolve({ ok: false, error: 'timeout' });
    }, timeoutMs);

    client.on("message", (msg) => {
      clearTimeout(timer);
      client.close();

      const malformedError = validateResponsePacket(msg, logger);
      if (malformedError) {
        resolve({ ok: false, raw: msg.toString("hex"), error: malformedError });
        return;
      }

      if (msg.readUInt8(1) !== id) {
        resolve({ ok: false, raw: msg.toString("hex"), error: "identifier_mismatch" });
        return;
      }

      if (!hasValidResponseAuthenticator(msg, authenticator, secret)) {
        if (logger) logger.warn("[radius] response authenticator mismatch; dropping response");
        resolve({ ok: false, raw: msg.toString("hex"), error: "authenticator_mismatch" });
        return;
      }

      const code = msg.readUInt8(0);

      // 2 = Access-Accept, 3 = Access-Reject, 11 = Access-Challenge
      if (code === 2 || code === 3 || code === 11) {
        // parse attributes for Class (type 25) - handle multiple classes and validate properly
        let offset = 20;
        let foundClass: string | undefined = undefined;
        const allClasses: string[] = [];
        const parsedAttributes: ParsedRadiusAttribute[] = [];

        while (offset + 2 <= msg.length) {
          const t = msg.readUInt8(offset);
          const l = msg.readUInt8(offset + 1);

          // Validate attribute length per RFC 2865
          if (l < 2) {
            if (logger) logger.warn('[radius] invalid attribute length < 2; stopping parse');
            break;
          }

          // ensure attribute does not run past the end of the packet
          if (offset + l > msg.length) {
            if (logger) logger.warn('[radius] attribute length runs past packet end; stopping parse');
            break;
          }

          const value = msg.subarray(offset + 2, offset + l);

          // NEW: Generic parsing
          try {
            parsedAttributes.push(decodeAttribute(t, value));
          } catch (e) {
             if (logger) logger.warn('[radius] error decoding attribute', { type: t, error: e });
          }

          // Check if this is our target attribute (Legacy logic preserved)
          let isTargetAttribute = false;
          let extractedValue: string | undefined = undefined;

          const targetAttributeId = options.assignmentAttributeId || 25;

          if (t === targetAttributeId) {
            if (t === 26 && options.vendorId !== undefined && options.vendorType !== undefined) {
              // Vendor-Specific Attribute (VSA) parsing
              if (value.length >= 6) {
                const vendorId = value.readUInt32BE(0);
                const vendorType = value.readUInt8(4);
                const vendorLength = value.readUInt8(5);

                if (vendorId === options.vendorId && vendorType === options.vendorType) {
                  const vendorValue = value.subarray(6, 6 + vendorLength - 2).toString("utf8");

                  if (options.valuePattern) {
                    // Extract value using regex pattern
                    const regex = new RegExp(options.valuePattern);
                    const match = vendorValue.match(regex);
                    if (match && match[1]) {
                      extractedValue = match[1];
                      isTargetAttribute = true;
                    }
                  } else {
                    // Use the full vendor value
                    extractedValue = vendorValue;
                    isTargetAttribute = true;
                  }
                }
              }
            } else {
              // Regular attribute parsing
              const attributeValue = value.toString("utf8");

              if (options.valuePattern) {
                // Extract value using regex pattern
                const regex = new RegExp(options.valuePattern);
                const match = attributeValue.match(regex);
                if (match && match[1]) {
                  extractedValue = match[1];
                  isTargetAttribute = true;
                }
              } else {
                // Use the full attribute value
                extractedValue = attributeValue;
                isTargetAttribute = true;
              }
            }
          }

          if (isTargetAttribute && extractedValue !== undefined) {
            allClasses.push(extractedValue);
            // Take the first assignment attribute encountered per RFC 2865 implementation choice
            if (!foundClass) {
              foundClass = extractedValue;
            }
          }

          offset += l;
        }

        const isOk = code === 2;
        const errorString = isOk
          ? undefined
          : (code === 3 ? 'access_reject' : 'access_challenge');

        resolve({
            ok: isOk,
            class: foundClass,
            attributes: parsedAttributes,
            raw: msg.toString("hex"),
            error: errorString
        });
      } else {
        resolve({ ok: false, raw: msg.toString("hex"), error: 'unknown_code' });
      }
    });

    client.on("error", (err) => {
      clearTimeout(timer);
      try {
        client.close();
      } catch (closeError: unknown) {
        if (logger) logger.debug('[radius] socket close after error failed', closeError);
      }
      reject(err);
    });

    // Compute Message-Authenticator (HMAC-MD5) per RFC2869 if present and then send.
    try {
      const hmac = crypto.createHmac('md5', Buffer.from(secret, 'utf8')).update(packet).digest();
      // find the Message-Authenticator attribute (type 80) in the packet and insert the value
      let attrOff = 20;
      while (attrOff + 2 <= packet.length) {
        const t = packet.readUInt8(attrOff);
        const l = packet.readUInt8(attrOff + 1);
        if (t === 80 && l === 18) {
          for (let i = 0; i < 16; i++) packet.writeUInt8(hmac.readUInt8(i), attrOff + 2 + i);
          break;
        }
        if (l < 2) break;
        attrOff += l;
      }
    } catch {
      // ignore hmac failures; some servers don't require Message-Authenticator
    }

    client.send(packet, port, host, (err) => {
      if (err) {
        clearTimeout(timer);
        client.close();
        reject(err);
      }
    });
  });
}

export async function radiusAccounting(
  host: string,
  request: RadiusAccountingRequest,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusResult> {
  const secret = options.secret;
  if (!secret) {
    throw new Error("RADIUS secret is required and cannot be empty");
  }

  validateAccountingRequest(request);

  const port = options.accountingPort ?? options.port ?? 1813;
  const timeoutMs = options.timeoutMs ?? 5000;

  if (logger) {
    logger.debug("[radius] accounting start", {
      host,
      user: request.username,
      sessionId: request.sessionId,
      statusType: request.statusType
    });
  }

  return new Promise((resolve, reject) => {
    const client = dgram.createSocket("udp4");
    const id = crypto.randomBytes(1).readUInt8(0);

    const attrs = buildAccountingAttributes(request);
    const attrBuf = Buffer.concat(attrs);
    const len = 20 + attrBuf.length;
    if (len > 0xffff) {
      throw new Error("[radius] accounting packet exceeds maximum RADIUS length");
    }

    const header = Buffer.alloc(20);
    header.writeUInt8(4, 0); // Accounting-Request
    header.writeUInt8(id, 1);
    header.writeUInt16BE(len, 2);

    // RFC2866 Request Authenticator for Accounting-Request is MD5 over packet with zero authenticator + secret.
    const packet = Buffer.concat([header, attrBuf]);
    const requestAuthenticator = crypto
      .createHash("md5")
      .update(Buffer.concat([packet, Buffer.from(secret, "utf8")]))
      .digest();
    requestAuthenticator.copy(packet, 4);

    const timer = setTimeout(() => {
      client.close();
      resolve({ ok: false, error: "timeout" });
    }, timeoutMs);

    client.on("message", (msg) => {
      clearTimeout(timer);
      client.close();

      const malformedError = validateResponsePacket(msg, logger);
      if (malformedError) {
        resolve({ ok: false, raw: msg.toString("hex"), error: malformedError });
        return;
      }

      if (msg.readUInt8(1) !== id) {
        resolve({ ok: false, raw: msg.toString("hex"), error: "identifier_mismatch" });
        return;
      }

      if (!hasValidResponseAuthenticator(msg, requestAuthenticator, secret)) {
        if (logger) logger.warn("[radius] accounting response authenticator mismatch; dropping response");
        resolve({ ok: false, raw: msg.toString("hex"), error: "authenticator_mismatch" });
        return;
      }

      const code = msg.readUInt8(0);
      const parsedAttributes = parseAttributes(msg, logger);

      if (code !== 5) {
        resolve({
          ok: false,
          attributes: parsedAttributes,
          raw: msg.toString("hex"),
          error: "unknown_code"
        });
        return;
      }

      resolve({
        ok: true,
        attributes: parsedAttributes,
        raw: msg.toString("hex")
      });
    });

    client.on("error", (err) => {
      clearTimeout(timer);
      try {
        client.close();
      } catch (closeError: unknown) {
        if (logger) logger.debug("[radius] socket close after error failed", closeError);
      }
      reject(err);
    });

    client.send(packet, port, host, (err) => {
      if (err) {
        clearTimeout(timer);
        client.close();
        reject(err);
      }
    });
  });
}
