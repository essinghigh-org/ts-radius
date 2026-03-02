export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

export class ConsoleLogger implements Logger {
  debug(message: string, ...args: unknown[]): void {
    console.log(`[debug] ${message}`, ...args);
  }
  info(message: string, ...args: unknown[]): void {
    console.info(`[info] ${message}`, ...args);
  }
  warn(message: string, ...args: unknown[]): void {
    console.warn(`[warn] ${message}`, ...args);
  }
  error(message: string, ...args: unknown[]): void {
    console.error(`[error] ${message}`, ...args);
  }
}

export interface ParsedAttribute {
  id: number;
  name: string;
  value: unknown;
  raw: string; // Hex string of value for reference
}

export interface ExtendedAttributeValue {
  format: "extended" | "long-extended";
  extendedType: number;
  data: string;
  flags?: number;
  hasMore?: boolean;
  malformed?: boolean;
  reason?: string;
}

export interface ExtendedRadiusAttribute extends ParsedAttribute {
  id: 241 | 242 | 243 | 244 | 245 | 246;
  value: ExtendedAttributeValue;
}

export interface VendorSpecificAttribute {
  id: 26;
  name: "Vendor-Specific";
  vendorId: number;
  value: unknown; // If parsed, structure; else hex string
  raw: string;
}

export type ParsedRadiusAttribute = ParsedAttribute | ExtendedRadiusAttribute | VendorSpecificAttribute;

export interface RadiusResult {
  ok: boolean;
  class?: string;
  attributes?: ParsedRadiusAttribute[];
  raw?: string;
  error?: string;
}

export interface RadiusChallengeContext {
  /** User-Name carried through the continuation flow. */
  username: string;
  /** 1-based challenge round index (incremented per Access-Challenge response). */
  round: number;
  /** Maximum permitted Access-Challenge rounds for this flow. */
  maxRounds: number;
  /** Hex-encoded State (Type 24) value to round-trip in the next Access-Request. */
  state: string;
  /** Hex-encoded Proxy-State (Type 33) values to round-trip in order. */
  proxyState: string[];
}

export interface RadiusChallengeContinuationOptions {
  /** Maximum Access-Challenge rounds allowed in the continuation flow (default: 3). */
  maxChallengeRounds?: number;
}

export interface RadiusChallengeResult extends RadiusResult {
  /** Continuation context available when error === "access_challenge" and context is valid. */
  challenge?: RadiusChallengeContext;
}

export interface RadiusAttribute {
  type: number;
  value: string | number | Buffer;
}

export type RadiusDynamicAuthorizationAttribute = RadiusAttribute;

export interface RadiusDynamicAuthorizationRequestBase {
  /** Optional session identification attribute (User-Name / type 1) */
  username?: string;
  /** Optional session identification attribute (Acct-Session-Id / type 44) */
  sessionId?: string;
  /** Additional RADIUS attributes for identification and/or authorization changes */
  attributes?: RadiusDynamicAuthorizationAttribute[];
}

export type RadiusCoaRequest = RadiusDynamicAuthorizationRequestBase;
export type RadiusDisconnectRequest = RadiusDynamicAuthorizationRequestBase;

export interface RadiusDynamicAuthorizationRequestIdentity {
  /** RFC5176 packet Identifier (1 octet). */
  identifier: number;
  /**
   * Optional fixed UDP source port for CoA/Disconnect sends.
   * When omitted and an identity object is reused by caller code,
   * implementations may resolve and persist an ephemeral source port.
   */
  sourcePort?: number;
  /**
   * Optional RFC5176 packet Request Authenticator (16 octets) override.
   * When omitted, the protocol layer computes the accounting-style
   * Request Authenticator per RFC2866/RFC5176.
   */
  requestAuthenticator?: Buffer;
}

export interface RadiusAccountingRequestIdentity {
  /** RFC2866 packet Identifier (1 octet). */
  identifier: number;
  /**
   * Optional fixed UDP source port for Accounting-Request sends.
   * When omitted and an identity object is reused by caller code,
   * implementations may resolve and persist an ephemeral source port.
   */
  sourcePort?: number;
}

export type RadiusErrorCauseSymbol =
  | "residual_session_context_removed"
  | "invalid_eap_packet"
  | "unsupported_attribute"
  | "missing_attribute"
  | "nas_identification_mismatch"
  | "invalid_request"
  | "unsupported_service"
  | "unsupported_extension"
  | "invalid_attribute_value"
  | "administratively_prohibited"
  | "request_not_routable"
  | "session_context_not_found"
  | "session_context_not_removable"
  | "other_proxy_processing_error"
  | "resources_unavailable"
  | "request_initiated"
  | "multiple_session_selection_unsupported";

export interface RadiusDynamicAuthorizationResult {
  ok: boolean;
  acknowledged: boolean;
  attributes?: ParsedRadiusAttribute[];
  raw?: string;
  error?: string;
  errorCause?: number;
  /** RFC5176 symbolic mapping for known Error-Cause codes; undefined for unknown/absent codes. */
  errorCauseSymbol?: RadiusErrorCauseSymbol;
}

export type RadiusCoaResult = RadiusDynamicAuthorizationResult;
export type RadiusDisconnectResult = RadiusDynamicAuthorizationResult;

export type ResponseLengthValidationPolicy = "strict" | "allow_trailing_bytes";
export type ResponseMessageAuthenticatorPolicy = "compatibility" | "strict";
export type RadiusAuthMethod = "pap" | "chap";

export interface RadiusProtocolOptions {
  secret: string;
  port?: number;
  accountingPort?: number;
  dynamicAuthorizationPort?: number;
  timeoutMs?: number;
  /** Access-Request credential attribute mode (default: "pap"). */
  authMethod?: RadiusAuthMethod;
  /** Optional deterministic CHAP Identifier override (used when authMethod is "chap"). */
  chapId?: number;
  /** Optional deterministic CHAP challenge override (used when authMethod is "chap"). */
  chapChallenge?: Buffer;
  assignmentAttributeId?: number;
  vendorId?: number;
  vendorType?: number;
  valuePattern?: string;
  /** Validate response source host/port against request target host/port (default: true). */
  validateResponseSource?: boolean;
  /**
   * Optional request identity override for Accounting-Request packets.
   * When provided, the Identifier is reused verbatim; sourcePort (if set)
   * binds the local UDP source port.
   */
  accountingRequestIdentity?: RadiusAccountingRequestIdentity;
  /**
   * Optional request identity override for CoA/Disconnect packets.
    * `identifier` is always used verbatim.
    * `sourcePort`, when provided, binds the local UDP source port.
    * `requestAuthenticator`, when provided, is used verbatim and must be 16 bytes.
    * If omitted, the protocol layer computes the accounting-style Request
    * Authenticator for the packet.
   */
  dynamicAuthorizationRequestIdentity?: RadiusDynamicAuthorizationRequestIdentity;
  /**
    * Access-response Message-Authenticator policy (authentication and auth-probe path).
   * - compatibility (default): warn on invalid value and continue.
   * - strict: reject malformed/invalid values.
    * Dynamic authorization responses always reject invalid *present*
    * Message-Authenticator values regardless of this policy.
   */
  responseMessageAuthenticatorPolicy?: ResponseMessageAuthenticatorPolicy;
  /**
   * Max absolute skew in seconds allowed for Event-Timestamp (Type 55)
   * in dynamic authorization responses when present.
   * Default: 300 seconds.
   */
  dynamicAuthorizationEventTimestampWindowSeconds?: number;
  /**
   * How response length mismatches are handled.
   * - strict (default for access-auth/status/dynamic-authorization):
   *   declared packet length must equal UDP datagram length.
   * - allow_trailing_bytes (default for accounting responses):
   *   accept datagrams with extra trailing bytes and parse only declared length.
   */
  responseLengthValidationPolicy?: ResponseLengthValidationPolicy;
}

export type RadiusSessionAccountingStatusType = "Start" | "Stop" | "Interim-Update";
export type RadiusOnOffAccountingStatusType = "Accounting-On" | "Accounting-Off";
export type RadiusAccountingStatusType = RadiusSessionAccountingStatusType | RadiusOnOffAccountingStatusType;

export type RadiusAccountingAttribute = RadiusAttribute;

interface RadiusAccountingRequestFields {
  /** Optional User-Name (type 1). Required for Start/Stop/Interim-Update. */
  username?: string;
  /**
   * Acct-Session-Id (type 44).
   * Required for Start/Stop/Interim-Update.
   * For Accounting-On/Accounting-Off, a session ID is auto-generated when omitted.
   */
  sessionId?: string;
  sessionTime?: number;
  inputOctets?: number;
  /**
   * 64-bit octet counter encoded into Acct-Input-Octets (low word) and
   * Acct-Input-Gigawords (high word). When provided alongside inputOctets,
   * this value takes precedence.
   */
  inputOctets64?: bigint;
  outputOctets?: number;
  /**
   * 64-bit octet counter encoded into Acct-Output-Octets (low word) and
   * Acct-Output-Gigawords (high word). When provided alongside outputOctets,
   * this value takes precedence.
   */
  outputOctets64?: bigint;
  inputPackets?: number;
  outputPackets?: number;
  delayTime?: number;
  terminateCause?: number;
  /**
   * Additional accounting attributes.
   * If neither NAS-IP-Address (4) nor NAS-Identifier (32) is supplied,
   * a default NAS-IP-Address value of 127.0.0.1 is injected.
   */
  attributes?: RadiusAccountingAttribute[];
}

export interface RadiusAccountingRequestBase extends RadiusAccountingRequestFields {
  username: string;
  sessionId: string;
}

export type RadiusAccountingOnOffRequest = RadiusAccountingRequestFields;

export type RadiusAccountingRequest =
  | (RadiusAccountingRequestBase & { statusType: RadiusSessionAccountingStatusType })
  | (RadiusAccountingOnOffRequest & { statusType: RadiusOnOffAccountingStatusType });

export interface RadiusRetryOptions {
  /** Total auth attempts per call, including the first attempt (default: 1) */
  maxAttempts?: number;
  /** Base delay before retry #1 in milliseconds (default: 100) */
  initialDelayMs?: number;
  /** Exponential multiplier for subsequent retry delays (default: 2) */
  backoffMultiplier?: number;
  /** Maximum delay cap for retry sleeps in milliseconds (default: 5000) */
  maxDelayMs?: number;
  /** Symmetric jitter ratio in [0, 1], where 0.5 means ±50% (default: 0) */
  jitterRatio?: number;
}

export type DynamicAuthorizationRetryIdentityMode = "per_attempt" | "stable";

export type HealthCheckProbeMode = "auth" | "status-server";

export interface RadiusConfig extends RadiusProtocolOptions {
  /** Primary RADIUS host */
  host: string;
  /** Ordered list of failover hosts (includes primary if desired) */
  hosts?: string[];
  /** Health check interval in milliseconds (default: 1800000 = 30m) */
  healthCheckIntervalMs?: number;
  /** Health check timeout in milliseconds (default: 5000) */
  healthCheckTimeoutMs?: number;
  /** Probe strategy for host health checks (default: "auth") */
  healthCheckProbeMode?: HealthCheckProbeMode;
  /** User for health check probes (required, including "status-server" mode for auth-fallback compatibility) */
  healthCheckUser: string;
  /** Password for health check probes (required, including "status-server" mode for auth-fallback compatibility) */
  healthCheckPassword: string;
  /** Retry behavior for authenticate() transport-level failures */
  retry?: RadiusRetryOptions;
  /**
   * Controls CoA/Disconnect retry identity behavior.
   * - per_attempt (default): each retry attempt uses a new packet identifier,
   *   producing a new computed accounting-style Request Authenticator.
   * - stable: retries to the same host reuse one identifier;
   *   failover to a different host uses a new identity (identifier/sourcePort).
   *   Request Authenticator is still computed by the protocol layer per packet.
   */
  dynamicAuthorizationRetryIdentityMode?: DynamicAuthorizationRetryIdentityMode;
}
