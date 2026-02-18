import dgram from "dgram";
import crypto from "crypto";
import type { Logger, RadiusResult, RadiusProtocolOptions, ParsedRadiusAttribute } from "./types";
import { decodeAttribute } from "./helpers";

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
    const id = crypto.randomBytes(1)[0];
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
        xored[b * 16 + i] = padded[b * 16 + i] ^ md5[i];
      }
      prev = xored.slice(b * 16, b * 16 + 16);
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
      if (!msg || msg.length < 20) {
        if (logger) logger.warn('[radius] received malformed response (too short)');
        resolve({ ok: false, raw: msg ? msg.toString("hex") : undefined, error: 'malformed_response' });
        return;
      }

      const code = msg.readUInt8(0);
      // Verify response authenticator per RFC2865 when secret is available to avoid spoofed replies.
      try {
        const respAuth = msg.slice(4, 20);
        // Recompute: MD5(Code + Identifier + Length + RequestAuthenticator + Attributes + SharedSecret)
        const lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16BE(msg.length, 0);
        const toHash = Buffer.concat([
          Buffer.from([msg.readUInt8(0)]),
          Buffer.from([msg.readUInt8(1)]),
          lenBuf,
          authenticator, // request authenticator we sent earlier
          msg.slice(20), // attributes from response
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

          const value = msg.slice(offset + 2, offset + l);

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
                  const vendorValue = value.slice(6, 6 + vendorLength - 2).toString("utf8");

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

        const isOk = (code === 2);
        let errorString: string | undefined = undefined;
        if (!isOk) {
            if (code === 3) errorString = 'access_reject';
            else if (code === 11) errorString = 'access_challenge';
            else errorString = 'unknown_code';
        }

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
      try { client.close(); } catch { }
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
          for (let i = 0; i < 16; i++) packet[attrOff + 2 + i] = hmac[i];
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
