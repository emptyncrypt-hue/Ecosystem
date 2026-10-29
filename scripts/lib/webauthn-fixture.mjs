import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

// A deliberately small, independent test authenticator. The Worker still parses
// the CBOR/COSE bytes and verifies real signatures with workerd's Web Crypto.
function cborHead(major, value) {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value <= 0xff) return Buffer.from([(major << 5) | 24, value]);
  if (value <= 0xffff) {
    const result = Buffer.alloc(3);
    result[0] = (major << 5) | 25;
    result.writeUInt16BE(value, 1);
    return result;
  }
  const result = Buffer.alloc(5);
  result[0] = (major << 5) | 26;
  result.writeUInt32BE(value, 1);
  return result;
}

function cbor(value) {
  if (Buffer.isBuffer(value)) return Buffer.concat([cborHead(2, value.length), value]);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([cborHead(3, bytes.length), bytes]);
  }
  if (Number.isSafeInteger(value)) return value < 0 ? cborHead(1, -1 - value) : cborHead(0, value);
  if (value instanceof Map) {
    return Buffer.concat([cborHead(5, value.size), ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)])]);
  }
  throw new TypeError('Unsupported synthetic CBOR value');
}

const hash = (value) => createHash('sha256').update(value).digest();
const base64url = (value) => Buffer.from(value).toString('base64url');

export function syntheticAuthenticator({ algorithm = 'ES256', credentialId = randomBytes(32) } = {}) {
  const { publicKey, privateKey } = algorithm === 'RS256'
    ? generateKeyPairSync('rsa', { modulusLength: 2048 })
    : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const cose = algorithm === 'RS256'
    ? new Map([[1, 3], [3, -257], [-1, Buffer.from(jwk.n, 'base64url')], [-2, Buffer.from(jwk.e, 'base64url')]])
    : new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]);
  const id = base64url(credentialId);
  let userHandle = null;

  function clientData(type, challenge, origin, { crossOrigin = false } = {}) {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin }));
  }

  function authenticatorData(rpId, counter, flags, attested = false) {
    const prefix = Buffer.alloc(37);
    hash(rpId).copy(prefix);
    prefix[32] = flags;
    prefix.writeUInt32BE(counter, 33);
    if (!attested) return prefix;
    const length = Buffer.alloc(2);
    length.writeUInt16BE(credentialId.length);
    return Buffer.concat([prefix, Buffer.alloc(16), length, credentialId, cbor(cose)]);
  }

  return {
    id,
    algorithm,
    registration(options, origin, { rpId = options.rp.id, challenge = options.challenge, counter = 0, flags = 0x45, type = 'webauthn.create', crossOrigin = false } = {}) {
      userHandle = options.user.id;
      const data = clientData(type, challenge, origin, { crossOrigin });
      const attestationObject = cbor(new Map([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', authenticatorData(rpId, counter, flags, true)],
      ]));
      return {
        id,
        rawId: id,
        type: 'public-key',
        authenticatorAttachment: 'cross-platform',
        clientExtensionResults: {},
        response: {
          clientDataJSON: base64url(data),
          attestationObject: base64url(attestationObject),
          transports: ['usb'],
        },
      };
    },
    authentication(options, origin, { rpId = options.rpId, challenge = options.challenge, counter = 0, flags = 0x05, type = 'webauthn.get', crossOrigin = false, corruptSignature = false, userHandle: responseUserHandle = userHandle } = {}) {
      const data = clientData(type, challenge, origin, { crossOrigin });
      const authData = authenticatorData(rpId, counter, flags);
      const signature = sign('sha256', Buffer.concat([authData, hash(data)]), privateKey);
      if (corruptSignature) signature[signature.length - 1] ^= 1;
      return {
        id,
        rawId: id,
        type: 'public-key',
        authenticatorAttachment: 'cross-platform',
        clientExtensionResults: {},
        response: {
          clientDataJSON: base64url(data),
          authenticatorData: base64url(authData),
          signature: base64url(signature),
          userHandle: responseUserHandle,
        },
      };
    },
  };
}
