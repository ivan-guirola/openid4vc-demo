import { base64url, decodeJwt, sha256, verifyJwt, type Jwt, type PublicJwk } from './jose.ts';
import { parseSdJwt, verifyPresentation } from './sdjwt.ts';

export interface Field {
  name: string;
  value: unknown;
  salt: string;
  disclosure: string;
  digest: string;
  position: number;
  shared: boolean;
}

export interface Part {
  kind: 'issuer-header' | 'issuer-payload' | 'issuer-signature' | 'disclosure' | 'kb-header' | 'kb-payload' | 'kb-signature';
  text: string;
  name?: string;
}

export type CheckId = 'issuer' | 'expiry' | 'disclosure' | 'holder' | 'nonce' | 'audience' | 'sd_hash';

export interface Check {
  id: CheckId;
  ok: boolean;
  name?: string;
  expected?: string;
  actual?: string;
}

export interface Inspection {
  issuer: Jwt & { signature: string };
  keyBinding: (Jwt & { signature: string }) | undefined;
  holderJwk: PublicJwk | undefined;
  fields: Field[];
  digests: string[];
  parts: Part[];
  sdHashInput: string;
  checks: Check[];
}

export interface InspectOptions {
  credential: string;
  presentation: string;
  issuerJwk: PublicJwk;
  nonce: string;
  audience: string;
  now?: number;
}

const signatureOf = (token: string) => token.split('.')[2] ?? '';

async function valid(token: string, jwk: PublicJwk | undefined) {
  if (!jwk) return false;
  return verifyJwt(token, jwk).then(
    () => true,
    () => false,
  );
}

function split(token: string, kinds: [Part['kind'], Part['kind'], Part['kind']]): Part[] {
  return token.split('.').map((text, index) => ({ kind: kinds[index], text }));
}

export interface Card {
  jwt: string;
  issuer: Jwt & { signature: string };
  digests: string[];
  fields: Field[];
}

/** Opens a stored credential: the signed part and every field with its salt and fingerprint. */
export async function describeCredential(credential: string, shared: Set<string> = new Set()): Promise<Card> {
  const { jwt, disclosures } = parseSdJwt(credential);
  const issuer = { ...decodeJwt(jwt), signature: signatureOf(jwt) };
  const digests: string[] = issuer.payload._sd ?? [];
  const fields: Field[] = [];
  for (const disclosure of disclosures) {
    const digest = await sha256(disclosure.encoded);
    fields.push({
      name: disclosure.name,
      value: disclosure.value,
      salt: disclosure.salt,
      disclosure: disclosure.encoded,
      digest,
      position: digests.indexOf(digest),
      shared: shared.has(disclosure.encoded),
    });
  }
  return { jwt, issuer, digests, fields };
}

/** Breaks a presentation into the pieces the verifier sees and re-runs every check it makes, keeping the values. */
export async function inspect(options: InspectOptions): Promise<Inspection> {
  const sent = parseSdJwt(options.presentation);
  const issuer = { ...decodeJwt(sent.jwt), signature: signatureOf(sent.jwt) };
  const digests: string[] = issuer.payload._sd ?? [];
  const { fields } = await describeCredential(options.credential, new Set(sent.disclosures.map((disclosure) => disclosure.encoded)));

  const keyBinding = sent.keyBinding ? { ...decodeJwt(sent.keyBinding), signature: signatureOf(sent.keyBinding) } : undefined;
  const holderJwk = issuer.payload.cnf?.jwk as PublicJwk | undefined;
  const sdHashInput = options.presentation.slice(0, options.presentation.lastIndexOf('~') + 1);
  const sdHash = await sha256(sdHashInput);
  const now = options.now ?? Math.floor(Date.now() / 1000);

  const checks: Check[] = [
    { id: 'issuer', ok: await valid(sent.jwt, options.issuerJwk) },
    { id: 'expiry', ok: typeof issuer.payload.exp !== 'number' || issuer.payload.exp >= now, actual: String(issuer.payload.exp) },
  ];
  for (const disclosure of sent.disclosures) {
    const digest = await sha256(disclosure.encoded);
    checks.push({ id: 'disclosure', name: disclosure.name, ok: digests.includes(digest), actual: digest });
  }
  checks.push(
    { id: 'holder', ok: !!sent.keyBinding && (await valid(sent.keyBinding, holderJwk)) },
    { id: 'nonce', ok: keyBinding?.payload.nonce === options.nonce, expected: options.nonce, actual: keyBinding?.payload.nonce },
    { id: 'audience', ok: keyBinding?.payload.aud === options.audience, expected: options.audience, actual: keyBinding?.payload.aud },
    { id: 'sd_hash', ok: keyBinding?.payload.sd_hash === sdHash, expected: keyBinding?.payload.sd_hash, actual: sdHash },
  );

  const parts: Part[] = [
    ...split(sent.jwt, ['issuer-header', 'issuer-payload', 'issuer-signature']),
    ...sent.disclosures.map((disclosure): Part => ({ kind: 'disclosure', text: disclosure.encoded, name: disclosure.name })),
    ...(sent.keyBinding ? split(sent.keyBinding, ['kb-header', 'kb-payload', 'kb-signature']) : []),
  ];

  return { issuer, keyBinding, holderJwk, fields, digests, parts, sdHashInput, checks };
}

export interface Tampered {
  forged: string;
  digest: string;
  found: boolean;
  error: string | undefined;
}

/** Rewrites one revealed field the way a dishonest wallet would, and runs the verifier on the result. */
export async function tamper(options: InspectOptions & { name: string; value: unknown }): Promise<Tampered> {
  const { jwt, disclosures } = parseSdJwt(options.presentation);
  const target = disclosures.find((disclosure) => disclosure.name === options.name);
  if (!target) throw new Error(`"${options.name}" was not shared`);

  const forged = base64url.encode(JSON.stringify([target.salt, target.name, options.value]));
  const digest = await sha256(forged);
  const digests: string[] = decodeJwt(jwt).payload._sd ?? [];
  const presentation = jwt + options.presentation.slice(jwt.length).replace(`~${target.encoded}~`, `~${forged}~`);
  const error = await verifyPresentation(presentation, {
    audience: options.audience,
    nonce: options.nonce,
    now: options.now,
    issuerKey: async () => options.issuerJwk,
  }).then(
    () => undefined,
    (reason: Error) => reason.message,
  );
  return { forged, digest, found: digests.includes(digest), error };
}
