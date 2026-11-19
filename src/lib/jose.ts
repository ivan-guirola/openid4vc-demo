export interface PublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

export interface KeyPair {
  privateKey: CryptoKey;
  publicJwk: PublicJwk;
  kid: string;
}

export interface Jwt {
  header: Record<string, any>;
  payload: Record<string, any>;
}

const ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGNATURE = { name: 'ECDSA', hash: 'SHA-256' } as const;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const base64url = {
  encode(input: Uint8Array | string): string {
    const bytes = typeof input === 'string' ? encoder.encode(input) : input;
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  decode(text: string): Uint8Array<ArrayBuffer> {
    const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  },
  text(text: string): string {
    return decoder.decode(base64url.decode(text));
  },
};

export async function sha256(text: string): Promise<string> {
  return base64url.encode(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text))));
}

export function randomId(bytes = 16): string {
  return base64url.encode(crypto.getRandomValues(new Uint8Array(bytes)));
}

export const thumbprint = ({ crv, kty, x, y }: PublicJwk) => sha256(JSON.stringify({ crv, kty, x, y }));

export async function generateKey(): Promise<KeyPair> {
  const pair = await crypto.subtle.generateKey(ALGORITHM, false, ['sign', 'verify']);
  const { x, y } = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const publicJwk: PublicJwk = { kty: 'EC', crv: 'P-256', x: x!, y: y! };
  return { privateKey: pair.privateKey, publicJwk, kid: await thumbprint(publicJwk) };
}

export async function signJwt(header: Record<string, unknown>, payload: Record<string, unknown>, key: KeyPair) {
  const input = `${base64url.encode(JSON.stringify(header))}.${base64url.encode(JSON.stringify(payload))}`;
  const signature = await crypto.subtle.sign(SIGNATURE, key.privateKey, encoder.encode(input));
  return `${input}.${base64url.encode(new Uint8Array(signature))}`;
}

export function decodeJwt(token: string): Jwt {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('not a JWT');
  try {
    return { header: JSON.parse(base64url.text(parts[0])), payload: JSON.parse(base64url.text(parts[1])) };
  } catch {
    throw new Error('not a JWT');
  }
}

export async function verifyJwt(token: string, jwk: PublicJwk): Promise<Jwt> {
  const jwt = decodeJwt(token);
  const [head, body, signature] = token.split('.');
  let valid = false;
  try {
    const { kty, crv, x, y } = jwk;
    const key = await crypto.subtle.importKey('jwk', { kty, crv, x, y }, ALGORITHM, false, ['verify']);
    valid =
      jwt.header.alg === 'ES256' &&
      (await crypto.subtle.verify(SIGNATURE, key, base64url.decode(signature), encoder.encode(`${head}.${body}`)));
  } catch {
    valid = false;
  }
  if (!valid) throw new Error('invalid signature');
  return jwt;
}
