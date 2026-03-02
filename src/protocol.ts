import { lookup } from "node:dns/promises";
import dgram, { type RemoteInfo } from "node:dgram";
import crypto from "node:crypto";
import { isIP, SocketAddress } from "node:net";

import type {
  Logger,
  ParsedRadiusAttribute,
  RadiusAccountingRequest,
  RadiusAccountingStatusType,
  RadiusCoaRequest,
  RadiusCoaResult,
  RadiusDisconnectRequest,
  RadiusDisconnectResult,
  RadiusErrorCauseSymbol,
  RadiusDynamicAuthorizationAttribute,
  RadiusDynamicAuthorizationRequestBase,
  RadiusDynamicAuthorizationResult,
  RadiusProtocolOptions,
  RadiusResult,
  ResponseLengthValidationPolicy,
  ResponseMessageAuthenticatorPolicy,
} from "./types";
import { decodeAttribute } from "./helpers";

const ACCOUNTING_STATUS_VALUES: Record<RadiusAccountingStatusType, number> = {
  Start: 1,
  Stop: 2,
  "Interim-Update": 3
};

const DISCONNECT_REQUEST_CODE = 40;
const DISCONNECT_ACK_CODE = 41;
const DISCONNECT_NAK_CODE = 42;
const COA_REQUEST_CODE = 43;
const COA_ACK_CODE = 44;
const COA_NAK_CODE = 45;
const ERROR_CAUSE_ATTRIBUTE_TYPE = 101;
const RFC5176_ERROR_CAUSE_SYMBOLS: Readonly<Partial<Record<number, RadiusErrorCauseSymbol>>> = {
  201: "residual_session_context_removed",
  202: "invalid_eap_packet",
  401: "unsupported_attribute",
  402: "missing_attribute",
  403: "nas_identification_mismatch",
  404: "invalid_request",
  405: "unsupported_service",
  406: "unsupported_extension",
  407: "invalid_attribute_value",
  501: "administratively_prohibited",
  502: "request_not_routable",
  503: "session_context_not_found",
  504: "session_context_not_removable",
  505: "other_proxy_processing_error",
  506: "resources_unavailable",
  507: "request_initiated",
  508: "multiple_session_selection_unsupported"
};

interface DynamicAuthorizationCodes {
  request: number;
  ack: number;
  nak: number;
  nakError: string;
}

function isUint32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function isRadiusAttributeType(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 255;
}

function isVendorType(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 255;
}

function validateExtractedAssignmentOptions(options: RadiusProtocolOptions): void {
  const assignmentAttributeId = options.assignmentAttributeId ?? 25;
  if (!isRadiusAttributeType(assignmentAttributeId)) {
    throw new Error("[radius] assignmentAttributeId must be an integer between 1 and 255");
  }

  const hasVendorId = options.vendorId !== undefined;
  const hasVendorType = options.vendorType !== undefined;
  const vendorId = options.vendorId;
  const vendorType = options.vendorType;

  if (assignmentAttributeId === 26 && hasVendorId !== hasVendorType) {
    throw new Error("[radius] vendorId and vendorType are both required when assignmentAttributeId is 26");
  }

  if (hasVendorId && (vendorId === undefined || !isUint32(vendorId))) {
    throw new Error("[radius] vendorId must be a uint32");
  }

  if (hasVendorType && (vendorType === undefined || !isVendorType(vendorType))) {
    throw new Error("[radius] vendorType must be an integer between 0 and 255");
  }
}

function extractAssignmentValue(rawValue: string, valuePattern: string | undefined, logger?: Logger): string | undefined {
  if (!valuePattern) {
    return rawValue;
  }

  try {
    const regex = new RegExp(valuePattern);
    const match = rawValue.match(regex);
    if (!match) {
      return undefined;
    }

    return match[1] ?? match[0];
  } catch (error: unknown) {
    if (logger) {
      logger.warn("[radius] invalid valuePattern; falling back to full attribute value", {
        valuePattern,
        error,
      });
    }
    return rawValue;
  }
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

function encodeCustomAttributeValue(
  attribute: RadiusDynamicAuthorizationAttribute
): Buffer {
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

function getResponseLengthValidationPolicy(options: RadiusProtocolOptions): ResponseLengthValidationPolicy {
  return options.responseLengthValidationPolicy === "allow_trailing_bytes"
    ? "allow_trailing_bytes"
    : "strict";
}

function validateResponsePacket(
  response: Buffer,
  options: RadiusProtocolOptions,
  logger?: Logger
): { packet: Buffer } | { error: "malformed_response" } {
  if (response.length < 20) {
    if (logger) logger.warn("[radius] received malformed response (too short)");
    return { error: "malformed_response" };
  }

  const declaredLength = response.readUInt16BE(2);
  if (declaredLength < 20) {
    if (logger) {
      logger.warn("[radius] received malformed response (declared length below minimum)", {
        declaredLength,
        actualLength: response.length
      });
    }
    return { error: "malformed_response" };
  }

  if (declaredLength > response.length) {
    if (logger) {
      logger.warn("[radius] received malformed response (declared length exceeds datagram length)", {
        declaredLength,
        actualLength: response.length
      });
    }
    return { error: "malformed_response" };
  }

  if (declaredLength < response.length) {
    const policy = getResponseLengthValidationPolicy(options);
    if (policy === "strict") {
      if (logger) {
        logger.warn("[radius] received malformed response (length mismatch)", {
          declaredLength,
          actualLength: response.length,
          policy
        });
      }
      return { error: "malformed_response" };
    }

    if (logger) {
      logger.warn("[radius] response has trailing bytes; truncating to declared length", {
        declaredLength,
        actualLength: response.length,
        policy
      });
    }
    return { packet: response.subarray(0, declaredLength) };
  }

  return { packet: response };
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
    if (!isRadiusAttributeType(attribute.type)) {
      throw new Error("[radius] accounting attribute type must be an integer between 1 and 255");
    }

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
    attrs.push(encodeCustomAttributeValue(attribute));
  }

  return attrs;
}

function validateDynamicAuthorizationRequest(request: RadiusDynamicAuthorizationRequestBase): void {
  const hasUsername = typeof request.username === "string" && request.username.trim().length > 0;
  const hasSessionId = typeof request.sessionId === "string" && request.sessionId.trim().length > 0;
  const hasAttributes = Array.isArray(request.attributes) && request.attributes.length > 0;

  if (request.username !== undefined && !hasUsername) {
    throw new Error("[radius] dynamic authorization request.username cannot be empty");
  }

  if (request.sessionId !== undefined && !hasSessionId) {
    throw new Error("[radius] dynamic authorization request.sessionId cannot be empty");
  }

  if (!hasUsername && !hasSessionId && !hasAttributes) {
    throw new Error(
      "[radius] dynamic authorization request must include username, sessionId, or at least one attribute"
    );
  }

  for (const attribute of request.attributes ?? []) {
    if (!isRadiusAttributeType(attribute.type)) {
      throw new Error("[radius] dynamic authorization attribute type must be an integer between 1 and 255");
    }

    if (typeof attribute.value === "number" && !isUint32(attribute.value)) {
      throw new Error(`[radius] dynamic authorization attribute ${String(attribute.type)} number values must be uint32`);
    }
  }
}

function buildDynamicAuthorizationAttributes(request: RadiusDynamicAuthorizationRequestBase): Buffer[] {
  const attrs: Buffer[] = [];

  if (request.username) {
    attrs.push(encodeStringAttribute(1, request.username));
  }

  if (request.sessionId) {
    attrs.push(encodeStringAttribute(44, request.sessionId));
  }

  for (const attribute of request.attributes ?? []) {
    attrs.push(encodeCustomAttributeValue(attribute));
  }

  return attrs;
}

function resolveDynamicAuthorizationRequestIdentity(
  options: RadiusProtocolOptions
): { identifier: number; requestAuthenticator: Buffer } {
  const identity = options.dynamicAuthorizationRequestIdentity;
  if (!identity) {
    return {
      identifier: crypto.randomBytes(1).readUInt8(0),
      requestAuthenticator: crypto.randomBytes(16),
    };
  }

  const { identifier, requestAuthenticator } = identity;

  if (!Number.isInteger(identifier) || identifier < 0 || identifier > 0xff) {
    throw new Error(
      "[radius] dynamic authorization request identity.identifier must be an integer between 0 and 255"
    );
  }

  if (!Buffer.isBuffer(requestAuthenticator) || requestAuthenticator.length !== 16) {
    throw new Error(
      "[radius] dynamic authorization request identity.requestAuthenticator must be a 16-byte Buffer"
    );
  }

  return {
    identifier,
    requestAuthenticator: Buffer.from(requestAuthenticator)
  };
}

function extractErrorCause(attributes: ParsedRadiusAttribute[]): number | undefined {
  const errorCause = attributes.find((attribute) => attribute.id === ERROR_CAUSE_ATTRIBUTE_TYPE);
  return typeof errorCause?.value === "number" ? errorCause.value : undefined;
}

function mapErrorCauseSymbol(errorCause: number | undefined): RadiusErrorCauseSymbol | undefined {
  if (errorCause === undefined) {
    return undefined;
  }

  return RFC5176_ERROR_CAUSE_SYMBOLS[errorCause];
}

// Minimal RADIUS client using UDP for Access-Request/Accept exchange.
// This is intentionally small and supports only PAP (User-Password) and Class attribute extraction.

const MESSAGE_AUTHENTICATOR_ATTRIBUTE_TYPE = 80;
const MESSAGE_AUTHENTICATOR_ATTRIBUTE_LENGTH = 18;

interface MessageAuthenticatorValidationResult {
  present: boolean;
  valid: boolean;
  reason?: string;
}

function normalizeHostValue(host: string): string {
  let normalized = host.trim().toLowerCase();
  if (normalized.startsWith("[") && normalized.endsWith("]")) {
    normalized = normalized.slice(1, -1);
  }

  const preserveIpv4MappedIpv6 = (value: string): string => {
    if (!value.startsWith("::ffff:")) {
      return value;
    }

    const mappedIpv4 = value.slice(7);
    if (isIP(mappedIpv4) === 4) {
      return mappedIpv4;
    }

    const segments = mappedIpv4.split(":");
    if (segments.length !== 2) {
      return value;
    }

    const upper = Number.parseInt(segments[0] ?? "", 16);
    const lower = Number.parseInt(segments[1] ?? "", 16);
    if (!Number.isInteger(upper) || !Number.isInteger(lower) || upper < 0 || upper > 0xffff || lower < 0 || lower > 0xffff) {
      return value;
    }

    const ipv4Octets = [
      upper >> 8,
      upper & 0xff,
      lower >> 8,
      lower & 0xff,
    ];

    return ipv4Octets.join(".");
  };

  normalized = preserveIpv4MappedIpv6(normalized);

  if (isIP(normalized) === 6) {
    const parsed = SocketAddress.parse(`[${normalized}]:0`);
    if (parsed?.family === "ipv6") {
      normalized = preserveIpv4MappedIpv6(parsed.address.toLowerCase());
    }
  }

  return normalized;
}

function createSocketForHost(host: string): ReturnType<typeof dgram.createSocket> {
  const socketType = isIP(normalizeHostValue(host)) === 6 ? "udp6" : "udp4";
  return dgram.createSocket(socketType);
}

function isKnownHmacCompatibilityError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const errorCode = (error as NodeJS.ErrnoException).code;
  if (
    errorCode === "ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE"
    || errorCode === "ERR_CRYPTO_INVALID_KEYLEN"
    || errorCode === "ERR_CRYPTO_FIPS_FORCED"
    || errorCode === "ERR_OSSL_EVP_UNSUPPORTED"
    || errorCode === "ERR_INVALID_ARG_TYPE"
  ) {
    return true;
  }

  return /hmac|digest|md5|crypto/i.test(error.message);
}

function handleMessageAuthenticatorComputationError(error: unknown, logger: Logger | undefined, context: string): void {
  if (isKnownHmacCompatibilityError(error)) {
    if (logger) {
      logger.warn("[radius] optional Message-Authenticator computation failed; continuing", {
        context,
        error,
      });
    }
    return;
  }

  if (logger) {
    logger.error("[radius] unexpected Message-Authenticator computation failure", {
      context,
      error,
    });
  }

  throw error;
}

async function resolveExpectedSourceHosts(host: string): Promise<Set<string>> {
  const normalizedHost = normalizeHostValue(host);
  const expectedHosts = new Set<string>([normalizedHost]);

  if (isIP(normalizedHost) !== 0) {
    return expectedHosts;
  }

  try {
    const records = await lookup(normalizedHost, { all: true });
    for (const record of records) {
      expectedHosts.add(normalizeHostValue(record.address));
    }
  } catch {
    // Keep compatibility for environments where DNS lookup is blocked.
  }

  return expectedHosts;
}

function isResponseSourceValid(remoteInfo: RemoteInfo, expectedHosts: Set<string>, expectedPort: number): boolean {
  if (remoteInfo.port !== expectedPort) {
    return false;
  }

  return expectedHosts.has(normalizeHostValue(remoteInfo.address));
}

function validateResponseMessageAuthenticator(
  msg: Buffer,
  secret: string,
  requestAuthenticator: Buffer
): MessageAuthenticatorValidationResult {
  let offset = 20;
  let messageAuthenticatorOffset: number | null = null;

  while (offset + 2 <= msg.length) {
    const type = msg.readUInt8(offset);
    const length = msg.readUInt8(offset + 1);

    if (length < 2 || offset + length > msg.length) {
      return {
        present: messageAuthenticatorOffset !== null,
        valid: false,
        reason: "invalid_attribute_length",
      };
    }

    if (type === MESSAGE_AUTHENTICATOR_ATTRIBUTE_TYPE) {
      if (messageAuthenticatorOffset !== null) {
        return {
          present: true,
          valid: false,
          reason: "duplicate_message_authenticator",
        };
      }

      if (length !== MESSAGE_AUTHENTICATOR_ATTRIBUTE_LENGTH) {
        return {
          present: true,
          valid: false,
          reason: "invalid_message_authenticator_length",
        };
      }

      messageAuthenticatorOffset = offset;
    }

    offset += length;
  }

  if (messageAuthenticatorOffset === null) {
    return { present: false, valid: true };
  }

  const verificationPacket = Buffer.from(msg);
  verificationPacket.fill(
    0,
    messageAuthenticatorOffset + 2,
    messageAuthenticatorOffset + MESSAGE_AUTHENTICATOR_ATTRIBUTE_LENGTH,
  );

  // For Access response packets, RFC behavior requires HMAC verification to use
  // the original Access-Request Authenticator in the packet header field.
  requestAuthenticator.copy(verificationPacket, 4, 0, 16);

  const expected = crypto
    .createHmac("md5", Buffer.from(secret, "utf8"))
    .update(verificationPacket)
    .digest();

  const actual = msg.subarray(
    messageAuthenticatorOffset + 2,
    messageAuthenticatorOffset + MESSAGE_AUTHENTICATOR_ATTRIBUTE_LENGTH,
  );

  if (!crypto.timingSafeEqual(expected, actual)) {
    return {
      present: true,
      valid: false,
      reason: "message_authenticator_mismatch",
    };
  }

  return { present: true, valid: true };
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

  const targetHost = normalizeHostValue(host);

  validateExtractedAssignmentOptions(options);

  const port = options.port || 1812;
  const timeoutMs = options.timeoutMs || 5000;
  const validateResponseSource = options.validateResponseSource !== false;
  const responseMessageAuthenticatorPolicy: ResponseMessageAuthenticatorPolicy =
    options.responseMessageAuthenticatorPolicy === "strict" ? "strict" : "compatibility";
  const expectedSourceHosts = validateResponseSource
    ? await resolveExpectedSourceHosts(targetHost)
    : null;

  if (logger) logger.debug('[radius] authenticate start', { host, user: username });

  return new Promise((resolve, reject) => {
    const client = createSocketForHost(targetHost);
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

    client.on("message", (msg, remoteInfo) => {
      clearTimeout(timer);
      client.close();

      const packetValidation = validateResponsePacket(msg, options, logger);
      if ("error" in packetValidation) {
        resolve({ ok: false, raw: msg.toString("hex"), error: packetValidation.error });
        return;
      }

      const response = packetValidation.packet;

      if (response.readUInt8(1) !== id) {
        if (logger) {
          logger.warn('[radius] received malformed response (identifier mismatch)', {
            expected: id,
            actual: response.readUInt8(1),
          });
        }
        resolve({ ok: false, raw: response.toString("hex"), error: "malformed_response" });
        return;
      }

      if (
        validateResponseSource
        && expectedSourceHosts
        && !isResponseSourceValid(remoteInfo, expectedSourceHosts, port)
      ) {
        if (logger) {
          logger.warn('[radius] received response from unexpected source', {
            expectedHosts: [...expectedSourceHosts],
            expectedPort: port,
            actualHost: remoteInfo.address,
            actualPort: remoteInfo.port,
          });
        }
        resolve({ ok: false, raw: response.toString("hex"), error: 'malformed_response' });
        return;
      }

      const messageAuthenticatorValidation = validateResponseMessageAuthenticator(response, secret, authenticator);
      if (responseMessageAuthenticatorPolicy === "strict" && !messageAuthenticatorValidation.present) {
        if (logger) {
          logger.warn('[radius] response Message-Authenticator missing in strict mode; dropping response');
        }
        resolve({ ok: false, raw: response.toString("hex"), error: 'malformed_response' });
        return;
      }

      if (messageAuthenticatorValidation.present && !messageAuthenticatorValidation.valid) {
        if (responseMessageAuthenticatorPolicy === "strict") {
          if (logger) {
            logger.warn('[radius] invalid response Message-Authenticator in strict mode; dropping response', {
              reason: messageAuthenticatorValidation.reason,
            });
          }
          resolve({ ok: false, raw: response.toString("hex"), error: 'malformed_response' });
          return;
        }

        if (logger) {
          logger.warn('[radius] invalid response Message-Authenticator (compatibility mode)', {
            reason: messageAuthenticatorValidation.reason,
          });
        }
      }

      if (!hasValidResponseAuthenticator(response, authenticator, secret)) {
        if (logger) logger.warn("[radius] response authenticator mismatch; dropping response");
        resolve({ ok: false, raw: response.toString("hex"), error: "authenticator_mismatch" });
        return;
      }

      const code = response.readUInt8(0);

      // 2 = Access-Accept, 3 = Access-Reject, 11 = Access-Challenge
      if (code === 2 || code === 3 || code === 11) {
        // parse attributes for Class (type 25) - handle multiple classes and validate properly
        let offset = 20;
        let foundClass: string | undefined = undefined;
        const allClasses: string[] = [];
        const parsedAttributes: ParsedRadiusAttribute[] = [];

        while (offset + 2 <= response.length) {
          const t = response.readUInt8(offset);
          const l = response.readUInt8(offset + 1);

          // Validate attribute length per RFC 2865
          if (l < 2) {
            if (logger) logger.warn('[radius] invalid attribute length < 2; stopping parse');
            break;
          }

          // ensure attribute does not run past the end of the packet
          if (offset + l > response.length) {
            if (logger) logger.warn('[radius] attribute length runs past packet end; stopping parse');
            break;
          }

          const value = response.subarray(offset + 2, offset + l);

          // NEW: Generic parsing
          try {
            parsedAttributes.push(decodeAttribute(t, value));
          } catch (e) {
             if (logger) logger.warn('[radius] error decoding attribute', { type: t, error: e });
          }

          // Check if this is our target attribute (Legacy logic preserved)
          let isTargetAttribute = false;
          let extractedValue: string | undefined = undefined;

          const targetAttributeId = options.assignmentAttributeId ?? 25;

          if (t === targetAttributeId) {
            if (t === 26 && options.vendorId !== undefined && options.vendorType !== undefined) {
              // Vendor-Specific Attribute (VSA) parsing
              if (value.length >= 6) {
                const vendorId = value.readUInt32BE(0);
                const vendorType = value.readUInt8(4);
                const vendorLength = value.readUInt8(5);

                if (vendorId === options.vendorId && vendorType === options.vendorType) {
                  if (vendorLength >= 2 && value.length >= 4 + vendorLength) {
                    const vendorValue = value.subarray(6, 4 + vendorLength).toString("utf8");
                    extractedValue = extractAssignmentValue(vendorValue, options.valuePattern, logger);
                    if (extractedValue !== undefined) {
                      isTargetAttribute = true;
                    }
                  } else if (logger) {
                    logger.warn("[radius] invalid vendor-specific assignment attribute length; skipping extraction", {
                      vendorId,
                      vendorType,
                      vendorLength,
                      attributeLength: value.length,
                    });
                  }
                }
              }
            } else {
              // Regular attribute parsing
              const attributeValue = value.toString("utf8");
              extractedValue = extractAssignmentValue(attributeValue, options.valuePattern, logger);
              if (extractedValue !== undefined) {
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
            raw: response.toString("hex"),
            error: errorString
        });
      } else {
        resolve({ ok: false, raw: response.toString("hex"), error: 'unknown_code' });
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
        if (t === MESSAGE_AUTHENTICATOR_ATTRIBUTE_TYPE && l === MESSAGE_AUTHENTICATOR_ATTRIBUTE_LENGTH) {
          for (let i = 0; i < 16; i++) packet.writeUInt8(hmac.readUInt8(i), attrOff + 2 + i);
          break;
        }
        if (l < 2) break;
        attrOff += l;
      }
    } catch (error: unknown) {
      handleMessageAuthenticatorComputationError(error, logger, "access-request");
    }

    client.send(packet, port, targetHost, (err) => {
      if (err) {
        clearTimeout(timer);
        client.close();
        reject(err);
      }
    });
  });
}

// RFC5997-oriented Status-Server health probe.
// A valid response indicates the server is alive; callers can decide fallback behavior.
export async function radiusStatusServerProbe(
  host: string,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusResult> {
  const secret = options.secret;
  if (!secret) {
    throw new Error('RADIUS secret is required and cannot be empty');
  }

  const targetHost = normalizeHostValue(host);

  const port = options.port || 1812;
  const timeoutMs = options.timeoutMs || 5000;
  const validateResponseSource = options.validateResponseSource !== false;
  const expectedSourceHosts = validateResponseSource
    ? await resolveExpectedSourceHosts(targetHost)
    : null;

  if (logger) logger.debug('[radius] status-server probe start', { host });

  return new Promise((resolve, reject) => {
    const client = createSocketForHost(targetHost);
    const id = crypto.randomBytes(1).readUInt8(0);
    const authenticator = crypto.randomBytes(16);

    const attrs: Buffer[] = [];
    // NAS-IP-Address (type 4) - optional, set to 127.0.0.1
    attrs.push(Buffer.concat([Buffer.from([4, 6]), Buffer.from([127, 0, 0, 1])]));
    // NAS-Port (type 5) - set to zero by default
    attrs.push(Buffer.concat([Buffer.from([5, 6]), Buffer.from([0, 0, 0, 0])]));
    // Message-Authenticator (type 80) - placeholder 16 bytes
    attrs.push(Buffer.concat([Buffer.from([80, 18]), Buffer.alloc(16, 0)]));

    const attrBuf = Buffer.concat(attrs);
    const len = 20 + attrBuf.length;
    const header = Buffer.alloc(20);
    header.writeUInt8(12, 0); // Status-Server
    header.writeUInt8(id, 1);
    header.writeUInt16BE(len, 2);
    authenticator.copy(header, 4);

    const packet = Buffer.concat([header, attrBuf]);

    // Compute Message-Authenticator (HMAC-MD5) if present.
    try {
      const hmac = crypto.createHmac('md5', Buffer.from(secret, 'utf8')).update(packet).digest();
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
    } catch (error: unknown) {
      handleMessageAuthenticatorComputationError(error, logger, "status-server-request");
    }

    const timer = setTimeout(() => {
      client.close();
      resolve({ ok: false, error: 'timeout' });
    }, timeoutMs);

    client.on("message", (msg, remoteInfo) => {
      clearTimeout(timer);
      client.close();

      const packetValidation = validateResponsePacket(msg, options, logger);
      if ("error" in packetValidation) {
        resolve({ ok: false, raw: msg.toString("hex"), error: packetValidation.error });
        return;
      }

      const response = packetValidation.packet;

      if (response.readUInt8(1) !== id) {
        if (logger) {
          logger.warn('[radius] received malformed status-server response (identifier mismatch)', {
            expected: id,
            actual: response.readUInt8(1),
          });
        }
        resolve({ ok: false, raw: response.toString("hex"), error: "identifier_mismatch" });
        return;
      }

      if (
        validateResponseSource
        && expectedSourceHosts
        && !isResponseSourceValid(remoteInfo, expectedSourceHosts, port)
      ) {
        if (logger) {
          logger.warn('[radius] received status-server response from unexpected source', {
            expectedHosts: [...expectedSourceHosts],
            expectedPort: port,
            actualHost: remoteInfo.address,
            actualPort: remoteInfo.port,
          });
        }
        resolve({ ok: false, raw: response.toString("hex"), error: 'malformed_response' });
        return;
      }

      if (!hasValidResponseAuthenticator(response, authenticator, secret)) {
        if (logger) logger.warn('[radius] status-server authenticator mismatch; dropping response');
        resolve({ ok: false, raw: response.toString("hex"), error: 'authenticator_mismatch' });
        return;
      }

      const code = response.readUInt8(0);
      // Valid response packet codes indicate server liveness.
      if (code === 2 || code === 3 || code === 5 || code === 11) {
        resolve({ ok: true, raw: response.toString("hex") });
        return;
      }

      resolve({ ok: false, raw: response.toString("hex"), error: 'unknown_code' });
    });

    client.on("error", (err) => {
      clearTimeout(timer);
      try {
        client.close();
      } catch (closeError: unknown) {
        if (logger) logger.debug('[radius] status-server socket close after error failed', closeError);
      }
      reject(err);
    });

    client.send(packet, port, targetHost, (err) => {
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

  const targetHost = normalizeHostValue(host);

  validateAccountingRequest(request);

  const port = options.accountingPort ?? options.port ?? 1813;
  const timeoutMs = options.timeoutMs ?? 5000;
  const validateResponseSource = options.validateResponseSource !== false;
  const expectedSourceHosts = validateResponseSource
    ? await resolveExpectedSourceHosts(targetHost)
    : null;

  const attrs = buildAccountingAttributes(request);
  const attrBuf = Buffer.concat(attrs);
  const len = 20 + attrBuf.length;
  if (len > 0xffff) {
    throw new Error("[radius] accounting packet exceeds maximum RADIUS length");
  }

  if (logger) {
    logger.debug("[radius] accounting start", {
      host,
      user: request.username,
      sessionId: request.sessionId,
      statusType: request.statusType
    });
  }

  return new Promise((resolve, reject) => {
    const client = createSocketForHost(targetHost);
    const id = crypto.randomBytes(1).readUInt8(0);

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

    client.on("message", (msg, remoteInfo) => {
      clearTimeout(timer);
      client.close();

      const packetValidation = validateResponsePacket(msg, options, logger);
      if ("error" in packetValidation) {
        resolve({ ok: false, raw: msg.toString("hex"), error: packetValidation.error });
        return;
      }

      const response = packetValidation.packet;

      if (response.readUInt8(1) !== id) {
        resolve({ ok: false, raw: response.toString("hex"), error: "identifier_mismatch" });
        return;
      }

      if (
        validateResponseSource
        && expectedSourceHosts
        && !isResponseSourceValid(remoteInfo, expectedSourceHosts, port)
      ) {
        if (logger) {
          logger.warn("[radius] received accounting response from unexpected source", {
            expectedHosts: [...expectedSourceHosts],
            expectedPort: port,
            actualHost: remoteInfo.address,
            actualPort: remoteInfo.port,
          });
        }
        resolve({ ok: false, raw: response.toString("hex"), error: "malformed_response" });
        return;
      }

      if (!hasValidResponseAuthenticator(response, requestAuthenticator, secret)) {
        if (logger) logger.warn("[radius] accounting response authenticator mismatch; dropping response");
        resolve({ ok: false, raw: response.toString("hex"), error: "authenticator_mismatch" });
        return;
      }

      const code = response.readUInt8(0);
      const parsedAttributes = parseAttributes(response, logger);

      if (code !== 5) {
        resolve({
          ok: false,
          attributes: parsedAttributes,
          raw: response.toString("hex"),
          error: "unknown_code"
        });
        return;
      }

      resolve({
        ok: true,
        attributes: parsedAttributes,
        raw: response.toString("hex")
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

    client.send(packet, port, targetHost, (err) => {
      if (err) {
        clearTimeout(timer);
        client.close();
        reject(err);
      }
    });
  });
}

async function sendDynamicAuthorization(
  host: string,
  request: RadiusDynamicAuthorizationRequestBase,
  options: RadiusProtocolOptions,
  codes: DynamicAuthorizationCodes,
  logger?: Logger
): Promise<RadiusDynamicAuthorizationResult> {
  const secret = options.secret;
  if (!secret) {
    throw new Error("RADIUS secret is required and cannot be empty");
  }

  const targetHost = normalizeHostValue(host);

  validateDynamicAuthorizationRequest(request);

  const port = options.dynamicAuthorizationPort ?? options.port ?? 3799;
  const timeoutMs = options.timeoutMs ?? 5000;
  const validateResponseSource = options.validateResponseSource !== false;

  const attrs = buildDynamicAuthorizationAttributes(request);
  const attrBuf = Buffer.concat(attrs);
  const len = 20 + attrBuf.length;
  if (len > 0xffff) {
    throw new Error("[radius] dynamic authorization packet exceeds maximum RADIUS length");
  }

  const expectedSourceHosts = validateResponseSource
    ? await resolveExpectedSourceHosts(targetHost)
    : null;

  if (logger) {
    logger.debug("[radius] dynamic-authorization start", {
      host,
      requestCode: codes.request,
      username: request.username,
      sessionId: request.sessionId
    });
  }

  const { identifier: id, requestAuthenticator } = resolveDynamicAuthorizationRequestIdentity(options);

  return new Promise((resolve, reject) => {
    const client = createSocketForHost(targetHost);

    const header = Buffer.alloc(20);
    header.writeUInt8(codes.request, 0);
    header.writeUInt8(id, 1);
    header.writeUInt16BE(len, 2);
    requestAuthenticator.copy(header, 4);

    const packet = Buffer.concat([header, attrBuf]);

    const timer = setTimeout(() => {
      client.close();
      resolve({ ok: false, acknowledged: false, error: "timeout" });
    }, timeoutMs);

    client.on("message", (msg, remoteInfo) => {
      if (
        validateResponseSource
        && expectedSourceHosts
        && !isResponseSourceValid(remoteInfo, expectedSourceHosts, port)
      ) {
        if (logger) {
          logger.warn("[radius] received dynamic authorization response from unexpected source", {
            expectedHosts: [...expectedSourceHosts],
            expectedPort: port,
            actualHost: remoteInfo.address,
            actualPort: remoteInfo.port,
          });
        }
        return;
      }

      clearTimeout(timer);
      client.close();

      const packetValidation = validateResponsePacket(msg, options, logger);
      if ("error" in packetValidation) {
        resolve({ ok: false, acknowledged: false, raw: msg.toString("hex"), error: packetValidation.error });
        return;
      }

      const response = packetValidation.packet;

      if (response.readUInt8(1) !== id) {
        resolve({ ok: false, acknowledged: false, raw: response.toString("hex"), error: "identifier_mismatch" });
        return;
      }

      if (!hasValidResponseAuthenticator(response, requestAuthenticator, secret)) {
        if (logger) logger.warn("[radius] dynamic authorization response authenticator mismatch; dropping response");
        resolve({ ok: false, acknowledged: false, raw: response.toString("hex"), error: "authenticator_mismatch" });
        return;
      }

      const code = response.readUInt8(0);
      const parsedAttributes = parseAttributes(response, logger);

      if (code === codes.ack) {
        resolve({
          ok: true,
          acknowledged: true,
          attributes: parsedAttributes,
          raw: response.toString("hex")
        });
        return;
      }

      if (code === codes.nak) {
        const errorCause = extractErrorCause(parsedAttributes);
        resolve({
          ok: false,
          acknowledged: false,
          attributes: parsedAttributes,
          raw: response.toString("hex"),
          error: codes.nakError,
          errorCause,
          errorCauseSymbol: mapErrorCauseSymbol(errorCause)
        });
        return;
      }

      resolve({
        ok: false,
        acknowledged: false,
        attributes: parsedAttributes,
        raw: response.toString("hex"),
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

    client.send(packet, port, targetHost, (err) => {
      if (err) {
        clearTimeout(timer);
        client.close();
        reject(err);
      }
    });
  });
}

export function radiusCoa(
  host: string,
  request: RadiusCoaRequest,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusCoaResult> {
  return sendDynamicAuthorization(
    host,
    request,
    options,
    {
      request: COA_REQUEST_CODE,
      ack: COA_ACK_CODE,
      nak: COA_NAK_CODE,
      nakError: "coa_nak"
    },
    logger
  );
}

export function radiusDisconnect(
  host: string,
  request: RadiusDisconnectRequest,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusDisconnectResult> {
  return sendDynamicAuthorization(
    host,
    request,
    options,
    {
      request: DISCONNECT_REQUEST_CODE,
      ack: DISCONNECT_ACK_CODE,
      nak: DISCONNECT_NAK_CODE,
      nakError: "disconnect_nak"
    },
    logger
  );
}
