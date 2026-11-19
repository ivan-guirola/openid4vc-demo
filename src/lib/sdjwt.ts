import { base64url, decodeJwt, randomId, sha256, signJwt, verifyJwt, type KeyPair, type PublicJwk } from './jose.ts';

export const SD_JWT_VC = 'dc+sd-jwt';

const RESERVED = new Set(['iss', 'iat', 'nbf', 'exp', 'vct', 'cnf', 'status', '_sd', '_sd_alg']);

export type Claims = Record<string, unknown>;

export interface Disclosure {
  encoded: string;
  salt: string;
  name: string;
  value: unknown;
}

export interface IssueOptions {
  issuer: string;
  vct: string;
  claims: Claims;
  disclosable: string[];
  holderJwk: PublicJwk;
  key: KeyPair;
  now?: number;
  ttl?: number;
}

export interface PresentOptions {
  audience: string;
  nonce: string;
  key: KeyPair;
  now?: number;
}

export interface VerifyOptions {
  audience: string;
  nonce: string;
  issuerKey: (issuer: string, kid: string | undefined) => Promise<PublicJwk>;
  now?: number;
}

export interface Verified {
  issuer: string;
  vct: string;
  claims: Claims;
  holderJwk: PublicJwk;
}

const seconds = () => Math.floor(Date.now() / 1000);

export async function issueSdJwt(options: IssueOptions): Promise<string> {
  const { issuer, vct, claims, disclosable, holderJwk, key, now = seconds(), ttl = 365 * 24 * 3600 } = options;
  const visible: Claims = {};
  const disclosures: string[] = [];
  const digests: string[] = [];

  for (const [name, value] of Object.entries(claims)) {
    if (!disclosable.includes(name)) {
      visible[name] = value;
      continue;
    }
    const disclosure = base64url.encode(JSON.stringify([randomId(), name, value]));
    disclosures.push(disclosure);
    digests.push(await sha256(disclosure));
  }

  const jwt = await signJwt(
    { alg: 'ES256', typ: SD_JWT_VC, kid: key.kid },
    { iss: issuer, iat: now, exp: now + ttl, vct, cnf: { jwk: holderJwk }, ...visible, _sd: digests.sort(), _sd_alg: 'sha-256' },
    key,
  );
  return [jwt, ...disclosures, ''].join('~');
}

export function parseSdJwt(text: string): { jwt: string; disclosures: Disclosure[]; keyBinding?: string } {
  const parts = text.split('~');
  if (parts.length < 2) throw new Error('not an SD-JWT');
  const disclosures = parts.slice(1, -1).map((encoded) => {
    try {
      const [salt, name, value] = JSON.parse(base64url.text(encoded));
      return { encoded, salt, name, value };
    } catch {
      throw new Error('malformed disclosure');
    }
  });
  return { jwt: parts[0], disclosures, keyBinding: parts[parts.length - 1] || undefined };
}

export async function present(credential: string, reveal: string[], options: PresentOptions): Promise<string> {
  const { jwt, disclosures } = parseSdJwt(credential);
  const visible = decodeJwt(jwt).payload;
  const chosen = reveal.flatMap((name) => {
    const disclosure = disclosures.find((item) => item.name === name);
    if (!disclosure && !(name in visible)) throw new Error(`the credential has no claim "${name}"`);
    return disclosure ? [disclosure.encoded] : [];
  });

  const body = [jwt, ...chosen, ''].join('~');
  const keyBinding = await signJwt(
    { alg: 'ES256', typ: 'kb+jwt' },
    { iat: options.now ?? seconds(), aud: options.audience, nonce: options.nonce, sd_hash: await sha256(body) },
    options.key,
  );
  return body + keyBinding;
}

export async function verifyPresentation(text: string, options: VerifyOptions): Promise<Verified> {
  const { jwt, disclosures, keyBinding } = parseSdJwt(text);
  const { header, payload } = decodeJwt(jwt);
  if (header.typ !== SD_JWT_VC) throw new Error('not an SD-JWT credential');

  const issuerKey = await options.issuerKey(payload.iss, header.kid);
  await verifyJwt(jwt, issuerKey).catch(() => {
    throw new Error('invalid issuer signature');
  });
  if (typeof payload.exp === 'number' && payload.exp < (options.now ?? seconds())) {
    throw new Error('credential expired');
  }

  const claims: Claims = {};
  for (const [name, value] of Object.entries(payload)) {
    if (!RESERVED.has(name)) claims[name] = value;
  }
  for (const disclosure of disclosures) {
    if (!payload._sd?.includes(await sha256(disclosure.encoded))) {
      throw new Error(`disclosure "${disclosure.name}" was not signed by the issuer`);
    }
    claims[disclosure.name] = disclosure.value;
  }

  const holderJwk = payload.cnf?.jwk as PublicJwk | undefined;
  if (!keyBinding || !holderJwk) throw new Error('key binding missing');
  const proof = await verifyJwt(keyBinding, holderJwk).catch(() => {
    throw new Error('key binding does not match the credential holder');
  });
  if (proof.header.typ !== 'kb+jwt') throw new Error('key binding has the wrong type');
  if (proof.payload.nonce !== options.nonce) throw new Error('nonce mismatch');
  if (proof.payload.aud !== options.audience) throw new Error('audience mismatch');
  if (proof.payload.sd_hash !== (await sha256(text.slice(0, text.lastIndexOf('~') + 1)))) {
    throw new Error('sd_hash mismatch');
  }

  return { issuer: payload.iss, vct: payload.vct, claims, holderJwk };
}
