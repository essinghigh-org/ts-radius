import dgram from "dgram";
import crypto from "crypto";
import type {
  Logger,
  ParsedRadiusAttribute,
  RadiusCoaRequest,
  RadiusCoaResult,
  RadiusDisconnectRequest,
  RadiusDisconnectResult,
  RadiusDynamicAuthorizationAttribute,
  RadiusDynamicAuthorizationRequestBase,
  RadiusProtocolOptions,
  RadiusResult
} from "./types";
import { decodeAttribute } from "./helpers";

// Minimal RADIUS client using UDP for Access-Request/Accept exchange.
// This is intentionally small and supports only PAP (User-Password) and Class attribute extraction.

const DISCONNECT_REQUEST_CODE = 40;
const DISCONNECT_ACK_CODE = 41;
const DISCONNECT_NAK_CODE = 42;
const COA_REQUEST_CODE = 43;
const COA_ACK_CODE = 44;
const COA_NAK_CODE = 45;

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

  const encoded = Buffer.alloc(4);
  encoded.writeUInt32BE(value, 0);
  return encodeRadiusAttribute(type, encoded);
}

function encodeDynamicAuthorizationAttribute(attribute: RadiusDynamicAuthorizationAttribute): Buffer {
  if (typeof attribute.value === "string") {
    return encodeStringAttribute(attribute.type, attribute.value);
  }

  if (typeof attribute.value === "number") {
    return encodeIntegerAttribute(attribute.type, attribute.value);
  }

  return encodeRadiusAttribute(attribute.type, attribute.value);
}

function validateDynamicAuthorizationRequest(
  request: RadiusDynamicAuthorizationRequestBase,
  commandName: "coa" | "disconnect"
): void {
  const hasUsername = typeof request.username === "string" && request.username.trim().length > 0;
  const hasSessionId = typeof request.sessionId === "string" && request.sessionId.trim().length > 0;
  const hasAdditionalAttributes = (request.attributes?.length ?? 0) > 0;

  if (request.username !== undefined && !hasUsername) {
    throw new Error(`[radius] ${commandName} request.username must not be empty`);
  }

  if (request.sessionId !== undefined && !hasSessionId) {
    throw new Error(`[radius] ${commandName} request.sessionId must not be empty`);
  }

  if (!hasUsername && !hasSessionId && !hasAdditionalAttributes) {
    throw new Error(`[radius] ${commandName} request must include username, sessionId, or attributes`);
  }

  for (const attribute of request.attributes ?? []) {
    if (typeof attribute.value === "number" && !isUint32(attribute.value)) {
      throw new Error(`[radius] ${commandName} attribute ${String(attribute.type)} number values must be uint32`);
    }
  }
}

function buildDynamicAuthorizationAttributes(request: RadiusDynamicAuthorizationRequestBase): Buffer[] {
  const attributes: Buffer[] = [];

  if (request.username) {
    attributes.push(encodeStringAttribute(1, request.username));
  }

  if (request.sessionId) {
    attributes.push(encodeStringAttribute(44, request.sessionId));
  }

  for (const attribute of request.attributes ?? []) {
    attributes.push(encodeDynamicAuthorizationAttribute(attribute));
  }

  return attributes;
}

function parseResponseAttributes(packet: Buffer, logger?: Logger): ParsedRadiusAttribute[] {
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

function extractErrorCause(attributes: ParsedRadiusAttribute[]): number | undefined {
  const attr = attributes.find((attribute) => attribute.id === 101);
  if (!attr || typeof attr.value !== "number") {
    return undefined;
  }

  return attr.value;
}

function hasValidResponseAuthenticator(response: Buffer, requestAuthenticator: Buffer, secret: string): boolean {
  const expectedAuthenticator = crypto
    .createHash("md5")
    .update(
      Buffer.concat([
        Buffer.from([response.readUInt8(0)]),
        Buffer.from([response.readUInt8(1)]),
        response.subarray(2, 4),
        requestAuthenticator,
        response.subarray(20),
        Buffer.from(secret, "utf8")
      ])
    )
    .digest();

  return expectedAuthenticator.equals(response.subarray(4, 20));
}

interface DynamicAuthorizationCodes {
  requestCode: number;
  ackCode: number;
  nakCode: number;
  nakError: "coa_nak" | "disconnect_nak";
  commandName: "coa" | "disconnect";
}

async function sendDynamicAuthorization(
  host: string,
  request: RadiusDynamicAuthorizationRequestBase,
  options: RadiusProtocolOptions,
  codes: DynamicAuthorizationCodes,
  logger?: Logger
): Promise<RadiusCoaResult> {
  const secret = options.secret;
  if (!secret) {
    throw new Error("RADIUS secret is required and cannot be empty");
  }

  validateDynamicAuthorizationRequest(request, codes.commandName);

  const port = options.dynamicAuthorizationPort ?? options.port ?? 3799;
  const timeoutMs = options.timeoutMs ?? 5000;

  if (logger) {
    logger.debug(`[radius] ${codes.commandName} start`, {
      host,
      user: request.username,
      sessionId: request.sessionId,
      port
    });
  }

  return await new Promise((resolve, reject) => {
    const client = dgram.createSocket("udp4");
    const id = crypto.randomBytes(1).readUInt8(0);

    const attributes = buildDynamicAuthorizationAttributes(request);
    const attrBuf = Buffer.concat(attributes);
    const len = 20 + attrBuf.length;
    if (len > 0xffff) {
      throw new Error(`[radius] ${codes.commandName} packet exceeds maximum RADIUS length`);
    }

    const header = Buffer.alloc(20);
    header.writeUInt8(codes.requestCode, 0);
    header.writeUInt8(id, 1);
    header.writeUInt16BE(len, 2);

    const packet = Buffer.concat([header, attrBuf]);
    const requestAuthenticator = crypto
      .createHash("md5")
      .update(Buffer.concat([packet, Buffer.from(secret, "utf8")]))
      .digest();
    requestAuthenticator.copy(packet, 4);

    const timer = setTimeout(() => {
      client.close();
      resolve({ ok: false, acknowledged: false, error: "timeout" });
    }, timeoutMs);

    client.on("message", (msg) => {
      clearTimeout(timer);
      client.close();

      if (msg.length < 20) {
        if (logger) logger.warn("[radius] received malformed response (too short)");
        resolve({ ok: false, acknowledged: false, raw: msg.toString("hex"), error: "malformed_response" });
        return;
      }

      const declaredLength = msg.readUInt16BE(2);
      if (declaredLength < 20 || declaredLength > msg.length) {
        if (logger) {
          logger.warn("[radius] received malformed response (length mismatch)", {
            declaredLength,
            actualLength: msg.length
          });
        }
        resolve({ ok: false, acknowledged: false, raw: msg.toString("hex"), error: "malformed_response" });
        return;
      }

      const responsePacket = msg.subarray(0, declaredLength);

      if (responsePacket.readUInt8(1) !== id) {
        resolve({
          ok: false,
          acknowledged: false,
          raw: responsePacket.toString("hex"),
          error: "identifier_mismatch"
        });
        return;
      }

      if (!hasValidResponseAuthenticator(responsePacket, requestAuthenticator, secret)) {
        if (logger) logger.warn(`[radius] ${codes.commandName} response authenticator mismatch; dropping response`);
        resolve({
          ok: false,
          acknowledged: false,
          raw: responsePacket.toString("hex"),
          error: "authenticator_mismatch"
        });
        return;
      }

      const code = responsePacket.readUInt8(0);
      const parsedAttributes = parseResponseAttributes(responsePacket, logger);
      const errorCause = extractErrorCause(parsedAttributes);

      if (code === codes.ackCode) {
        resolve({
          ok: true,
          acknowledged: true,
          attributes: parsedAttributes,
          raw: responsePacket.toString("hex"),
          errorCause
        });
        return;
      }

      if (code === codes.nakCode) {
        resolve({
          ok: false,
          acknowledged: false,
          attributes: parsedAttributes,
          raw: responsePacket.toString("hex"),
          error: codes.nakError,
          errorCause
        });
        return;
      }

      resolve({
        ok: false,
        acknowledged: false,
        attributes: parsedAttributes,
        raw: responsePacket.toString("hex"),
        error: "unknown_code"
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

      // Minimal sanity checks
      if (msg.length < 20) {
        if (logger) logger.warn('[radius] received malformed response (too short)');
        resolve({ ok: false, raw: msg.toString("hex"), error: 'malformed_response' });
        return;
      }

      const code = msg.readUInt8(0);
      // Verify response authenticator per RFC2865 when secret is available to avoid spoofed replies.
      try {
        const respAuth = msg.subarray(4, 20);
        // Recompute: MD5(Code + Identifier + Length + RequestAuthenticator + Attributes + SharedSecret)
        const lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16BE(msg.length, 0);
        const toHash = Buffer.concat([
          Buffer.from([msg.readUInt8(0)]),
          Buffer.from([msg.readUInt8(1)]),
          lenBuf,
          authenticator, // request authenticator we sent earlier
          msg.subarray(20), // attributes from response
          Buffer.from(secret, "utf8"),
        ]);
        const expected = crypto.createHash("md5").update(toHash).digest();
        if (!expected.equals(respAuth)) {
          if (logger) logger.warn('[radius] response authenticator mismatch; dropping response');
          resolve({ ok: false, raw: msg.toString("hex"), error: 'authenticator_mismatch' });
          return;
        }
      } catch (e) {
        // Do not fail the entire flow on verification error; just warn and continue parsing.
        if (logger) logger.warn('[radius] response authenticator verification error', e);
      }

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

export async function radiusCoa(
  host: string,
  request: RadiusCoaRequest,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusCoaResult> {
  const result = await sendDynamicAuthorization(
    host,
    request,
    options,
    {
      requestCode: COA_REQUEST_CODE,
      ackCode: COA_ACK_CODE,
      nakCode: COA_NAK_CODE,
      nakError: "coa_nak",
      commandName: "coa"
    },
    logger
  );

  return result;
}

export async function radiusDisconnect(
  host: string,
  request: RadiusDisconnectRequest,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusDisconnectResult> {
  const result = await sendDynamicAuthorization(
    host,
    request,
    options,
    {
      requestCode: DISCONNECT_REQUEST_CODE,
      ackCode: DISCONNECT_ACK_CODE,
      nakCode: DISCONNECT_NAK_CODE,
      nakError: "disconnect_nak",
      commandName: "disconnect"
    },
    logger
  );

  return result;
}
