import { lookup } from "node:dns/promises";
import dgram, { type RemoteInfo } from "node:dgram";
import crypto from "node:crypto";
import { isIP, SocketAddress } from "node:net";

import type {
  Logger,
  ParsedRadiusAttribute,
  RadiusChallengeContext,
  RadiusChallengeContinuationOptions,
  RadiusChallengeResult,
  RadiusAccountingRequest,
  RadiusAccountingRequestIdentity,
  RadiusSessionAccountingStatusType,
  RadiusAccountingStatusType,
  RadiusCoaRequest,
  RadiusCoaResult,
  RadiusDisconnectRequest,
  RadiusDisconnectResult,
  RadiusErrorCauseSymbol,
  RadiusDynamicAuthorizationAttribute,
  RadiusDynamicAuthorizationRequestBase,
  RadiusDynamicAuthorizationResult,
  RadiusAuthMethod,
  RadiusProtocolOptions,
  RadiusResult,
  ResponseLengthValidationPolicy,
  ResponseMessageAuthenticatorPolicy,
} from "./types";
import { decodeAttribute } from "./helpers";

const ACCOUNTING_STATUS_VALUES: Record<RadiusAccountingStatusType, number> = {
  Start: 1,
  Stop: 2,
  "Interim-Update": 3,
  "Accounting-On": 7,
  "Accounting-Off": 8,
};

const SESSION_ACCOUNTING_STATUS_TYPES: ReadonlySet<RadiusSessionAccountingStatusType> = new Set([
  "Start",
  "Stop",
  "Interim-Update",
]);

const MAX_RADIUS_ATTRIBUTE_VALUE_LENGTH = 253;
const MAX_PAP_PASSWORD_BYTES = 128;
const MAX_ACCOUNTING_PACKET_LENGTH = 4095;
const NAS_IP_ADDRESS_ATTRIBUTE_TYPE = 4;
const NAS_IDENTIFIER_ATTRIBUTE_TYPE = 32;
const DEFAULT_NAS_IP_ADDRESS_VALUE = Buffer.from([127, 0, 0, 1]);

const UINT32_MASK_BIGINT = 0xffff_ffffn;
const UINT64_MAX_BIGINT = 0xffff_ffff_ffff_ffffn;

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

function isUdpPort(value: number): boolean {
  return Number.isInteger(value) && value >= 1 && value <= 0xffff;
}

function isUint64(value: bigint): boolean {
  return value >= 0n && value <= UINT64_MAX_BIGINT;
}

function splitUint64ToWords(value: bigint): { lowWord: number; highWord: number } {
  return {
    lowWord: Number(value & UINT32_MASK_BIGINT),
    highWord: Number((value >> 32n) & UINT32_MASK_BIGINT),
  };
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

  if (value.length > MAX_RADIUS_ATTRIBUTE_VALUE_LENGTH) {
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

function resolveAuthenticationMethod(options: RadiusProtocolOptions): RadiusAuthMethod {
  const authMethod: unknown = options.authMethod;

  if (authMethod === undefined || authMethod === "pap") {
    return "pap";
  }

  if (authMethod === "chap") {
    return "chap";
  }

  throw new Error("[radius] authMethod must be 'pap' or 'chap'");
}

function buildPapPasswordValue(password: string, secret: string, authenticator: Buffer): Buffer {
  const passwordBuffer = Buffer.from(password, "utf8");

  if (passwordBuffer.length > MAX_PAP_PASSWORD_BYTES) {
    throw new Error("[radius] PAP password must be at most 128 bytes");
  }

  const blockCount = Math.ceil(passwordBuffer.length / 16) || 1;
  const paddedPassword = Buffer.alloc(blockCount * 16, 0);
  passwordBuffer.copy(paddedPassword);

  const encryptedPassword = Buffer.alloc(paddedPassword.length);
  // For each 16-byte block, MD5(secret + previous) where previous is authenticator for block 0,
  // and the previous encrypted block for subsequent blocks (RFC2865 section 5.2).
  let previousBlock = authenticator;
  for (let blockIndex = 0; blockIndex < blockCount; blockIndex++) {
    const digest = crypto
      .createHash("md5")
      .update(Buffer.concat([Buffer.from(secret, "utf8"), previousBlock]))
      .digest();

    for (let byteIndex = 0; byteIndex < 16; byteIndex++) {
      const blockOffset = blockIndex * 16 + byteIndex;
      const encryptedByte = paddedPassword.readUInt8(blockOffset) ^ digest.readUInt8(byteIndex);
      encryptedPassword.writeUInt8(encryptedByte, blockOffset);
    }

    previousBlock = encryptedPassword.subarray(blockIndex * 16, blockIndex * 16 + 16);
  }

  return encryptedPassword;
}

function resolveChapIdentifier(options: RadiusProtocolOptions): number {
  const chapId = options.chapId ?? crypto.randomBytes(1).readUInt8(0);

  if (!Number.isInteger(chapId) || chapId < 0 || chapId > 0xff) {
    throw new Error("[radius] chapId must be an integer between 0 and 255");
  }

  return chapId;
}

function resolveChapChallenge(options: RadiusProtocolOptions): Buffer {
  const chapChallenge = options.chapChallenge;

  if (chapChallenge === undefined) {
    return crypto.randomBytes(16);
  }

  if (!Buffer.isBuffer(chapChallenge)) {
    throw new Error("[radius] chapChallenge must be a Buffer");
  }

  if (chapChallenge.length < 1 || chapChallenge.length > 253) {
    throw new Error("[radius] chapChallenge must be between 1 and 253 bytes");
  }

  return Buffer.from(chapChallenge);
}

function buildChapPasswordValue(password: string, chapId: number, chapChallenge: Buffer): Buffer {
  const chapIdBuffer = Buffer.from([chapId]);
  const chapDigest = crypto
    .createHash("md5")
    .update(Buffer.concat([chapIdBuffer, Buffer.from(password, "utf8"), chapChallenge]))
    .digest();

  return Buffer.concat([chapIdBuffer, chapDigest]);
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

function parseAttributes(
  packet: Buffer,
  logger?: Logger
): { attributes: ParsedRadiusAttribute[] } | { error: "malformed_response" } {
  const attributes: ParsedRadiusAttribute[] = [];
  let offset = 20;

  while (offset + 2 <= packet.length) {
    const t = packet.readUInt8(offset);
    const l = packet.readUInt8(offset + 1);

    if (l < 2) {
      if (logger) logger.warn("[radius] invalid attribute length < 2; rejecting response");
      return { error: "malformed_response" };
    }

    if (offset + l > packet.length) {
      if (logger) logger.warn("[radius] attribute length runs past packet end; rejecting response");
      return { error: "malformed_response" };
    }

    const value = packet.subarray(offset + 2, offset + l);
    try {
      attributes.push(decodeAttribute(t, value));
    } catch (error: unknown) {
      if (logger) logger.warn("[radius] error decoding attribute", { type: t, error });
    }

    offset += l;
  }

  if (offset !== packet.length) {
    if (logger) logger.warn("[radius] response attributes contain a truncated header; rejecting response");
    return { error: "malformed_response" };
  }

  return { attributes };
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

function requiresAccountingSessionIdentifiers(
  statusType: RadiusAccountingStatusType
): statusType is RadiusSessionAccountingStatusType {
  return SESSION_ACCOUNTING_STATUS_TYPES.has(statusType as RadiusSessionAccountingStatusType);
}

function validateAccountingRequest(request: RadiusAccountingRequest): void {
  const hasUsername = typeof request.username === "string" && request.username.trim().length > 0;
  const hasSessionId = typeof request.sessionId === "string" && request.sessionId.trim().length > 0;

  if (requiresAccountingSessionIdentifiers(request.statusType)) {
    if (!hasUsername) {
      throw new Error("[radius] accounting request.username is required");
    }

    if (!hasSessionId) {
      throw new Error("[radius] accounting request.sessionId is required");
    }
  } else {
    if (request.username !== undefined && !hasUsername) {
      throw new Error("[radius] accounting request.username cannot be empty");
    }

    if (request.sessionId !== undefined && !hasSessionId) {
      throw new Error("[radius] accounting request.sessionId cannot be empty");
    }
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

  const octetCounter64Fields: Array<[string, unknown]> = [
    ["inputOctets64", request.inputOctets64],
    ["outputOctets64", request.outputOctets64],
  ];

  for (const [fieldName, fieldValue] of octetCounter64Fields) {
    if (fieldValue !== undefined && (typeof fieldValue !== "bigint" || !isUint64(fieldValue))) {
      throw new Error(`[radius] accounting request.${fieldName} must be uint64`);
    }
  }

  const customAccountingTypes = new Set((request.attributes ?? []).map((attribute) => attribute.type));

  if (request.inputOctets64 !== undefined && (customAccountingTypes.has(42) || customAccountingTypes.has(52))) {
    throw new Error(
      "[radius] accounting request.attributes cannot include Acct-Input-Octets (42) or Acct-Input-Gigawords (52) when inputOctets64 is provided"
    );
  }

  if (request.outputOctets64 !== undefined && (customAccountingTypes.has(43) || customAccountingTypes.has(53))) {
    throw new Error(
      "[radius] accounting request.attributes cannot include Acct-Output-Octets (43) or Acct-Output-Gigawords (53) when outputOctets64 is provided"
    );
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

function resolveAccountingSessionId(request: RadiusAccountingRequest): string {
  if (typeof request.sessionId === "string" && request.sessionId.trim().length > 0) {
    return request.sessionId;
  }

  if (requiresAccountingSessionIdentifiers(request.statusType)) {
    throw new Error("[radius] accounting request.sessionId is required");
  }

  return `acct-onoff-${String(Date.now())}-${crypto.randomUUID()}`;
}

function resolveAccountingRequestIdentity(options: RadiusProtocolOptions): RadiusAccountingRequestIdentity {
  const identity = options.accountingRequestIdentity;
  if (!identity) {
    return {
      identifier: crypto.randomBytes(1).readUInt8(0)
    };
  }

  if (!Number.isInteger(identity.identifier) || identity.identifier < 0 || identity.identifier > 0xff) {
    throw new Error(
      "[radius] accounting request identity.identifier must be an integer between 0 and 255"
    );
  }

  if (identity.sourcePort !== undefined && !isUdpPort(identity.sourcePort)) {
    throw new Error(
      "[radius] accounting request identity.sourcePort must be an integer between 1 and 65535"
    );
  }

  return identity;
}

function hasAccountingNasIdentifier(request: RadiusAccountingRequest): boolean {
  return (request.attributes ?? []).some((attribute) =>
    attribute.type === NAS_IP_ADDRESS_ATTRIBUTE_TYPE || attribute.type === NAS_IDENTIFIER_ATTRIBUTE_TYPE
  );
}

function buildAccountingAttributes(request: RadiusAccountingRequest): Buffer[] {
  const attrs: Buffer[] = [];
  const resolvedSessionId = resolveAccountingSessionId(request);

  if (typeof request.username === "string" && request.username.trim().length > 0) {
    attrs.push(encodeStringAttribute(1, request.username));
  }

  attrs.push(encodeIntegerAttribute(40, ACCOUNTING_STATUS_VALUES[request.statusType]));
  attrs.push(encodeStringAttribute(44, resolvedSessionId));

  if (!hasAccountingNasIdentifier(request)) {
    attrs.push(encodeRadiusAttribute(NAS_IP_ADDRESS_ATTRIBUTE_TYPE, DEFAULT_NAS_IP_ADDRESS_VALUE));
  }

  if (request.delayTime !== undefined) {
    attrs.push(encodeIntegerAttribute(41, request.delayTime));
  }

  if (request.inputOctets64 !== undefined) {
    const { lowWord, highWord } = splitUint64ToWords(request.inputOctets64);
    attrs.push(encodeIntegerAttribute(42, lowWord));
    attrs.push(encodeIntegerAttribute(52, highWord));
  } else if (request.inputOctets !== undefined) {
    attrs.push(encodeIntegerAttribute(42, request.inputOctets));
  }

  if (request.outputOctets64 !== undefined) {
    const { lowWord, highWord } = splitUint64ToWords(request.outputOctets64);
    attrs.push(encodeIntegerAttribute(43, lowWord));
    attrs.push(encodeIntegerAttribute(53, highWord));
  } else if (request.outputOctets !== undefined) {
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
): { identifier: number; requestAuthenticator?: Buffer } {
  const identity = options.dynamicAuthorizationRequestIdentity;
  if (!identity) {
    return {
      identifier: crypto.randomBytes(1).readUInt8(0),
    };
  }

  const { identifier, requestAuthenticator } = identity;

  if (!Number.isInteger(identifier) || identifier < 0 || identifier > 0xff) {
    throw new Error(
      "[radius] dynamic authorization request identity.identifier must be an integer between 0 and 255"
    );
  }

  if (requestAuthenticator === undefined) {
    return {
      identifier,
    };
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

function resolveDynamicAuthorizationEventTimestampWindowSeconds(options: RadiusProtocolOptions): number {
  const configuredWindow = options.dynamicAuthorizationEventTimestampWindowSeconds;
  if (configuredWindow === undefined) {
    return DEFAULT_DYNAMIC_AUTHORIZATION_EVENT_TIMESTAMP_WINDOW_SECONDS;
  }

  if (!Number.isInteger(configuredWindow) || configuredWindow < 0) {
    throw new Error("[radius] dynamicAuthorizationEventTimestampWindowSeconds must be a non-negative integer");
  }

  return configuredWindow;
}

function validateDynamicAuthorizationEventTimestampFreshness(
  attributes: ParsedRadiusAttribute[],
  maxSkewSeconds: number
): EventTimestampFreshnessValidationResult {
  const eventTimestampAttributes = attributes.filter((attribute) => attribute.id === EVENT_TIMESTAMP_ATTRIBUTE_TYPE);
  if (eventTimestampAttributes.length === 0) {
    return {
      present: false,
      valid: true,
    };
  }

  const nowMs = Date.now();
  const maxSkewMs = maxSkewSeconds * 1000;

  for (const eventTimestampAttribute of eventTimestampAttributes) {
    if (!(eventTimestampAttribute.value instanceof Date)) {
      return {
        present: true,
        valid: false,
        reason: "event_timestamp_not_date",
      };
    }

    const eventTimestampMs = eventTimestampAttribute.value.getTime();
    if (!Number.isFinite(eventTimestampMs)) {
      return {
        present: true,
        valid: false,
        reason: "event_timestamp_invalid",
      };
    }

    if (Math.abs(nowMs - eventTimestampMs) > maxSkewMs) {
      return {
        present: true,
        valid: false,
        reason: "event_timestamp_out_of_window",
      };
    }
  }

  return {
    present: true,
    valid: true,
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
// This is intentionally small and supports PAP/CHAP authentication and Class attribute extraction.

const MESSAGE_AUTHENTICATOR_ATTRIBUTE_TYPE = 80;
const MESSAGE_AUTHENTICATOR_ATTRIBUTE_LENGTH = 18;
const EVENT_TIMESTAMP_ATTRIBUTE_TYPE = 55;
const DEFAULT_DYNAMIC_AUTHORIZATION_EVENT_TIMESTAMP_WINDOW_SECONDS = 300;
const DEFAULT_MAX_CHALLENGE_ROUNDS = 3;

interface AccessRequestContinuation {
  stateHex?: string;
  proxyStateHex?: string[];
}

interface MessageAuthenticatorValidationResult {
  present: boolean;
  valid: boolean;
  reason?: string;
}

interface EventTimestampFreshnessValidationResult {
  present: boolean;
  valid: boolean;
  reason?: string;
}

function normalizeHexValue(value: string, allowEmpty: boolean = false): string | null {
  const normalized = value.trim().toLowerCase();

  if (normalized.length === 0) {
    return allowEmpty ? "" : null;
  }

  if (normalized.length % 2 !== 0) {
    return null;
  }

  if (!/^[0-9a-f]+$/.test(normalized)) {
    return null;
  }

  return normalized;
}

function normalizeMaxChallengeRounds(value: number | undefined): number {
  if (!Number.isInteger(value) || value === undefined || value < 1) {
    return DEFAULT_MAX_CHALLENGE_ROUNDS;
  }

  return value;
}

function extractAttributeHexValues(
  attributes: ParsedRadiusAttribute[] | undefined,
  attributeId: number
): string[] {
  if (!attributes) {
    return [];
  }

  return attributes
    .filter((attribute) => attribute.id === attributeId)
    .map((attribute) => attribute.raw);
}

function normalizeChallengeContext(context: RadiusChallengeContext): RadiusChallengeContext | null {
  const username = typeof context.username === "string"
    ? context.username.trim()
    : "";

  if (username.length === 0) {
    return null;
  }

  if (!Number.isInteger(context.round) || context.round < 1) {
    return null;
  }

  if (!Number.isInteger(context.maxRounds) || context.maxRounds < 1 || context.round > context.maxRounds) {
    return null;
  }

  const normalizedState = normalizeHexValue(context.state);
  if (normalizedState === null) {
    return null;
  }

  if (!Array.isArray(context.proxyState)) {
    return null;
  }

  const normalizedProxyState: string[] = [];
  for (const proxyStateValue of context.proxyState) {
    if (typeof proxyStateValue !== "string") {
      return null;
    }

    const normalizedProxyStateValue = normalizeHexValue(proxyStateValue, true);
    if (normalizedProxyStateValue === null) {
      return null;
    }

    normalizedProxyState.push(normalizedProxyStateValue);
  }

  return {
    username,
    round: context.round,
    maxRounds: context.maxRounds,
    state: normalizedState,
    proxyState: normalizedProxyState,
  };
}

function toMalformedChallengeContextResult(result: RadiusResult, logger?: Logger): RadiusChallengeResult {
  if (logger) {
    logger.warn("[radius] malformed Access-Challenge continuation context");
  }

  return {
    ...result,
    error: "malformed_challenge_context",
    challenge: undefined,
  };
}

function toChallengeAwareResult(
  result: RadiusResult,
  username: string,
  maxRounds: number,
  previousContext: RadiusChallengeContext | undefined,
  logger?: Logger
): RadiusChallengeResult {
  if (result.error !== "access_challenge") {
    return { ...result };
  }

  const stateValues = extractAttributeHexValues(result.attributes, 24);
  if (stateValues.length !== 1) {
    return toMalformedChallengeContextResult(result, logger);
  }

  const normalizedState = normalizeHexValue(stateValues[0] ?? "");
  if (normalizedState === null) {
    return toMalformedChallengeContextResult(result, logger);
  }

  const proxyStateValues = extractAttributeHexValues(result.attributes, 33);
  const normalizedProxyStateValues: string[] = [];
  for (const proxyStateValue of proxyStateValues) {
    const normalizedProxyStateValue = normalizeHexValue(proxyStateValue, true);
    if (normalizedProxyStateValue === null) {
      return toMalformedChallengeContextResult(result, logger);
    }
    normalizedProxyStateValues.push(normalizedProxyStateValue);
  }

  const nextRound = (previousContext?.round ?? 0) + 1;
  if (nextRound > maxRounds) {
    if (logger) {
      logger.warn("[radius] Access-Challenge continuation max rounds exceeded", {
        maxRounds,
        currentRound: previousContext?.round ?? 0,
        nextRound,
      });
    }

    return {
      ...result,
      error: "challenge_round_limit_exceeded",
      challenge: undefined,
    };
  }

  return {
    ...result,
    challenge: {
      username,
      round: nextRound,
      maxRounds,
      state: normalizedState,
      proxyState: normalizedProxyStateValues,
    },
  };
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

async function radiusAuthenticateRequest(
  host: string,
  username: string,
  password: string,
  options: RadiusProtocolOptions,
  logger?: Logger,
  continuation?: AccessRequestContinuation
): Promise<RadiusResult> {
  const secret = options.secret;
  if (!secret) {
    throw new Error('RADIUS secret is required and cannot be empty');
  }

  const targetHost = normalizeHostValue(host);

  validateExtractedAssignmentOptions(options);
  const authMethod = resolveAuthenticationMethod(options);
  const usernameBuffer = Buffer.from(username, "utf8");

  if (usernameBuffer.length > MAX_RADIUS_ATTRIBUTE_VALUE_LENGTH) {
    throw new Error("[radius] User-Name must encode to at most 253 bytes");
  }

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
    attrs.push(encodeRadiusAttribute(1, usernameBuffer));

    if (authMethod === "chap") {
      // CHAP-Password (type 3): 1-octet CHAP identifier + 16-octet MD5 digest.
      const chapId = resolveChapIdentifier(options);
      const chapChallenge = resolveChapChallenge(options);
      const chapPasswordValue = buildChapPasswordValue(password, chapId, chapChallenge);

      attrs.push(encodeRadiusAttribute(3, chapPasswordValue));
      attrs.push(encodeRadiusAttribute(60, chapChallenge));
    } else {
      // User-Password (type 2) - PAP per RFC2865 with proper 16-byte block chaining
      const papPasswordValue = buildPapPasswordValue(password, secret, authenticator);
      attrs.push(encodeRadiusAttribute(2, papPasswordValue));
    }

    if (continuation?.stateHex !== undefined) {
      attrs.push(encodeRadiusAttribute(24, Buffer.from(continuation.stateHex, "hex")));
    }

    for (const proxyStateHex of continuation?.proxyStateHex ?? []) {
      attrs.push(encodeRadiusAttribute(33, Buffer.from(proxyStateHex, "hex")));
    }

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
        const parsedAttributes: ParsedRadiusAttribute[] = [];

        while (offset + 2 <= response.length) {
          const t = response.readUInt8(offset);
          const l = response.readUInt8(offset + 1);

          // Validate attribute length per RFC 2865
          if (l < 2) {
            if (logger) logger.warn('[radius] invalid attribute length < 2; rejecting response');
            resolve({ ok: false, raw: response.toString("hex"), error: "malformed_response" });
            return;
          }

          // ensure attribute does not run past the end of the packet
          if (offset + l > response.length) {
            if (logger) logger.warn('[radius] attribute length runs past packet end; rejecting response');
            resolve({ ok: false, raw: response.toString("hex"), error: "malformed_response" });
            return;
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
            // Take the first assignment attribute encountered per RFC 2865 implementation choice
            if (!foundClass) {
              foundClass = extractedValue;
            }
          }

          offset += l;
        }

        if (offset !== response.length) {
          if (logger) logger.warn('[radius] response attributes contain a truncated header; rejecting response');
          resolve({ ok: false, raw: response.toString("hex"), error: "malformed_response" });
          return;
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

export async function radiusAuthenticate(
  host: string,
  username: string,
  password: string,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusResult> {
  return radiusAuthenticateRequest(host, username, password, options, logger);
}

export async function radiusAuthenticateWithContinuation(
  host: string,
  username: string,
  password: string,
  options: RadiusProtocolOptions,
  logger?: Logger,
  continuationOptions?: RadiusChallengeContinuationOptions
): Promise<RadiusChallengeResult> {
  const maxRounds = normalizeMaxChallengeRounds(continuationOptions?.maxChallengeRounds);
  const result = await radiusAuthenticateRequest(host, username, password, options, logger);

  return toChallengeAwareResult(result, username, maxRounds, undefined, logger);
}

export async function radiusContinueAuthenticate(
  host: string,
  password: string,
  context: RadiusChallengeContext,
  options: RadiusProtocolOptions,
  logger?: Logger
): Promise<RadiusChallengeResult> {
  const normalizedContext = normalizeChallengeContext(context);
  if (!normalizedContext) {
    return toMalformedChallengeContextResult({ ok: false, error: "malformed_challenge_context" }, logger);
  }

  if (normalizedContext.round > normalizedContext.maxRounds) {
    if (logger) {
      logger.warn("[radius] Access-Challenge continuation blocked by max rounds safeguard", {
        round: normalizedContext.round,
        maxRounds: normalizedContext.maxRounds,
      });
    }

    return { ok: false, error: "challenge_round_limit_exceeded" };
  }

  const result = await radiusAuthenticateRequest(
    host,
    normalizedContext.username,
    password,
    options,
    logger,
    {
      stateHex: normalizedContext.state,
      proxyStateHex: normalizedContext.proxyState,
    },
  );

  return toChallengeAwareResult(result, normalizedContext.username, normalizedContext.maxRounds, normalizedContext, logger);
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
  const requestIdentity = resolveAccountingRequestIdentity(options);
  const responseValidationOptions: RadiusProtocolOptions = options.responseLengthValidationPolicy === undefined
    ? { ...options, responseLengthValidationPolicy: "allow_trailing_bytes" }
    : options;
  const expectedSourceHosts = validateResponseSource
    ? await resolveExpectedSourceHosts(targetHost)
    : null;

  const attrs = buildAccountingAttributes(request);
  const attrBuf = Buffer.concat(attrs);
  const len = 20 + attrBuf.length;
  if (len > MAX_ACCOUNTING_PACKET_LENGTH) {
    throw new Error("[radius] accounting packet exceeds RFC maximum length (4095 bytes)");
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
    const id = requestIdentity.identifier;

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

      const packetValidation = validateResponsePacket(msg, responseValidationOptions, logger);
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
      const parsedAttributesResult = parseAttributes(response, logger);
      if ("error" in parsedAttributesResult) {
        resolve({ ok: false, raw: response.toString("hex"), error: parsedAttributesResult.error });
        return;
      }

      const parsedAttributes = parsedAttributesResult.attributes;

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

    const sendPacket = (): void => {
      client.send(packet, port, targetHost, (err) => {
        if (err) {
          clearTimeout(timer);
          client.close();
          reject(err);
        }
      });
    };

    if (requestIdentity.sourcePort !== undefined) {
      client.bind(requestIdentity.sourcePort, () => {
        sendPacket();
      });
      return;
    }

    if (options.accountingRequestIdentity) {
      client.bind(0, () => {
        const localAddress = client.address();
        if (typeof localAddress !== "string") {
          requestIdentity.sourcePort = localAddress.port;
        }
        sendPacket();
      });
      return;
    }

    sendPacket();
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
  const dynamicAuthorizationEventTimestampWindowSeconds =
    resolveDynamicAuthorizationEventTimestampWindowSeconds(options);

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

  const { identifier: id, requestAuthenticator: requestAuthenticatorOverride } =
    resolveDynamicAuthorizationRequestIdentity(options);

  return new Promise((resolve, reject) => {
    const client = createSocketForHost(targetHost);

    const header = Buffer.alloc(20);
    header.writeUInt8(codes.request, 0);
    header.writeUInt8(id, 1);
    header.writeUInt16BE(len, 2);

    const packet = Buffer.concat([header, attrBuf]);
    const requestAuthenticator = requestAuthenticatorOverride
      ? Buffer.from(requestAuthenticatorOverride)
      : crypto
          .createHash("md5")
          .update(Buffer.concat([packet, Buffer.from(secret, "utf8")]))
          .digest();
    requestAuthenticator.copy(packet, 4);

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

      const messageAuthenticatorValidation = validateResponseMessageAuthenticator(response, secret, requestAuthenticator);
      if (messageAuthenticatorValidation.present && !messageAuthenticatorValidation.valid) {
        if (logger) {
          logger.warn("[radius] invalid dynamic authorization response Message-Authenticator; dropping response", {
            reason: messageAuthenticatorValidation.reason,
          });
        }
        resolve({ ok: false, acknowledged: false, raw: response.toString("hex"), error: "malformed_response" });
        return;
      }

      if (!hasValidResponseAuthenticator(response, requestAuthenticator, secret)) {
        if (logger) logger.warn("[radius] dynamic authorization response authenticator mismatch; dropping response");
        resolve({ ok: false, acknowledged: false, raw: response.toString("hex"), error: "authenticator_mismatch" });
        return;
      }

      const code = response.readUInt8(0);
      const parsedAttributesResult = parseAttributes(response, logger);
      if ("error" in parsedAttributesResult) {
        resolve({
          ok: false,
          acknowledged: false,
          raw: response.toString("hex"),
          error: parsedAttributesResult.error
        });
        return;
      }

      const parsedAttributes = parsedAttributesResult.attributes;
      const eventTimestampFreshnessValidation = validateDynamicAuthorizationEventTimestampFreshness(
        parsedAttributes,
        dynamicAuthorizationEventTimestampWindowSeconds
      );
      if (eventTimestampFreshnessValidation.present && !eventTimestampFreshnessValidation.valid) {
        if (logger) {
          logger.warn("[radius] dynamic authorization response Event-Timestamp failed freshness validation", {
            reason: eventTimestampFreshnessValidation.reason,
            maxSkewSeconds: dynamicAuthorizationEventTimestampWindowSeconds,
          });
        }
        resolve({
          ok: false,
          acknowledged: false,
          raw: response.toString("hex"),
          error: "malformed_response"
        });
        return;
      }

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
