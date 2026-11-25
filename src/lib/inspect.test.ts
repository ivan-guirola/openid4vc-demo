import { beforeAll, describe, expect, it } from 'vitest';
import { generateKey, sha256, type KeyPair } from './jose.ts';
import { describeCredential, inspect, tamper } from './inspect.ts';
import { issueSdJwt, present } from './sdjwt.ts';

const now = 1_800_000_000;
const claims = { given_name: 'Ana', family_name: 'García', birthdate: '1990-04-12', age_over_18: true };

let issuer: KeyPair;
let holder: KeyPair;
let credential: string;
let presentation: string;

beforeAll(async () => {
  [issuer, holder] = await Promise.all([generateKey(), generateKey()]);
  credential = await issueSdJwt({
    issuer: 'https://issuer.example',
    vct: 'urn:example:resident-card',
    claims,
    disclosable: Object.keys(claims),
    holderJwk: holder.publicJwk,
    key: issuer,
    now,
  });
  presentation = await present(credential, ['age_over_18'], { audience: 'verifier', nonce: 'n-1', key: holder, now: now + 5 });
});

const options = () => ({ credential, presentation, issuerJwk: issuer.publicJwk, nonce: 'n-1', audience: 'verifier', now: now + 10 });

describe('inspect', () => {
  it('lists every field of the card with its salt and its place among the signed digests', async () => {
    const result = await inspect(options());

    expect(result.fields.map((field) => field.name).sort()).toEqual(Object.keys(claims).sort());
    for (const field of result.fields) {
      expect(field.digest).toBe(await sha256(field.disclosure));
      expect(result.digests[field.position]).toBe(field.digest);
      expect(field.salt.length).toBeGreaterThan(10);
    }
  });

  it('marks only the chosen fields as shared', async () => {
    const shared = (await inspect(options())).fields.filter((field) => field.shared).map((field) => field.name);
    expect(shared).toEqual(['age_over_18']);
  });

  it('passes every check for an honest presentation', async () => {
    const { checks } = await inspect(options());
    expect(checks.map((check) => check.id)).toEqual(['issuer', 'expiry', 'disclosure', 'holder', 'nonce', 'audience', 'sd_hash']);
    expect(checks.every((check) => check.ok)).toBe(true);
  });

  it('fails the nonce and audience checks when they do not match the request', async () => {
    const { checks } = await inspect({ ...options(), nonce: 'other', audience: 'someone-else' });
    const failed = checks.filter((check) => !check.ok).map((check) => check.id);
    expect(failed).toEqual(['nonce', 'audience']);
  });

  it('fails the issuer check with another key', async () => {
    const { checks } = await inspect({ ...options(), issuerJwk: holder.publicJwk });
    expect(checks.find((check) => check.id === 'issuer')?.ok).toBe(false);
  });

  it('splits the token into the issuer part, the disclosures and the proof', async () => {
    const { parts } = await inspect(options());
    expect(parts.map((part) => part.kind)).toEqual([
      'issuer-header',
      'issuer-payload',
      'issuer-signature',
      'disclosure',
      'kb-header',
      'kb-payload',
      'kb-signature',
    ]);
    expect(parts[3].name).toBe('age_over_18');
  });

  it('computes sd_hash over everything before the proof', async () => {
    const result = await inspect(options());
    expect(result.sdHashInput.endsWith('~')).toBe(true);
    expect(presentation.startsWith(result.sdHashInput)).toBe(true);
    expect(result.keyBinding?.payload.sd_hash).toBe(await sha256(result.sdHashInput));
  });
});

describe('describeCredential', () => {
  it('opens the stored card with every field hidden behind a signed fingerprint', async () => {
    const card = await describeCredential(credential);
    expect(card.issuer.header).toMatchObject({ alg: 'ES256', typ: 'dc+sd-jwt' });
    expect(card.issuer.payload.cnf.jwk).toEqual(holder.publicJwk);
    expect(card.fields).toHaveLength(4);
    expect(card.fields.every((field) => !field.shared && card.digests[field.position] === field.digest)).toBe(true);
    expect(credential.startsWith(card.jwt)).toBe(true);
  });
});

describe('tamper', () => {
  it('produces a digest the issuer never signed and the verifier rejects it', async () => {
    const result = await tamper({ ...options(), name: 'age_over_18', value: false });
    expect(result.found).toBe(false);
    expect(result.error).toBe('disclosure "age_over_18" was not signed by the issuer');
  });

  it('refuses a field that was not shared', async () => {
    await expect(tamper({ ...options(), name: 'given_name', value: 'Eve' })).rejects.toThrow('was not shared');
  });
});
