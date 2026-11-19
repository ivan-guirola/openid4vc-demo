import { beforeAll, describe, expect, it } from 'vitest';
import { decodeJwt, generateKey, type KeyPair } from './jose.ts';
import { issueSdJwt, parseSdJwt, present, verifyPresentation } from './sdjwt.ts';

const now = 1_800_000_000;
const claims = { given_name: 'Ana', family_name: 'García', birthdate: '1990-04-12', age_over_18: true };
const all = Object.keys(claims);

let issuer: KeyPair;
let holder: KeyPair;
let stranger: KeyPair;

beforeAll(async () => {
  [issuer, holder, stranger] = await Promise.all([generateKey(), generateKey(), generateKey()]);
});

const issue = (overrides: Partial<Parameters<typeof issueSdJwt>[0]> = {}) =>
  issueSdJwt({
    issuer: 'https://issuer.example',
    vct: 'urn:example:resident-card',
    claims,
    disclosable: all,
    holderJwk: holder.publicJwk,
    key: issuer,
    now,
    ttl: 3600,
    ...overrides,
  });

const show = (credential: string, reveal: string[], overrides: Partial<Parameters<typeof present>[2]> = {}) =>
  present(credential, reveal, { audience: 'verifier', nonce: 'n-1', key: holder, now: now + 5, ...overrides });

const verify = (presentation: string, overrides: Partial<Parameters<typeof verifyPresentation>[1]> = {}) =>
  verifyPresentation(presentation, {
    audience: 'verifier',
    nonce: 'n-1',
    now: now + 10,
    issuerKey: async () => issuer.publicJwk,
    ...overrides,
  });

describe('issuing', () => {
  it('keeps the disclosable claims out of the signed part', async () => {
    const { jwt, disclosures } = parseSdJwt(await issue());
    const { header, payload } = decodeJwt(jwt);

    expect(header).toMatchObject({ alg: 'ES256', typ: 'dc+sd-jwt', kid: issuer.kid });
    expect(payload).toMatchObject({
      iss: 'https://issuer.example',
      vct: 'urn:example:resident-card',
      iat: now,
      exp: now + 3600,
      _sd_alg: 'sha-256',
      cnf: { jwk: holder.publicJwk },
    });
    expect(payload._sd).toHaveLength(4);
    expect(Object.keys(payload)).not.toContain('given_name');
    expect(disclosures.map((d) => d.name).sort()).toEqual([...all].sort());
  });

  it('leaves the other claims readable by everyone', async () => {
    const { jwt, disclosures } = parseSdJwt(await issue({ disclosable: ['birthdate'] }));

    expect(decodeJwt(jwt).payload).toMatchObject({ given_name: 'Ana', age_over_18: true });
    expect(disclosures.map((d) => d.name)).toEqual(['birthdate']);
  });

  it('uses a different salt for every claim and every credential', async () => {
    const first = parseSdJwt(await issue()).disclosures;
    const second = parseSdJwt(await issue()).disclosures;
    const salts = [...first, ...second].map((d) => d.salt);

    expect(new Set(salts).size).toBe(8);
  });
});

describe('presenting', () => {
  it('reveals only the chosen claims', async () => {
    const result = await verify(await show(await issue(), ['age_over_18']));

    expect(result.claims).toEqual({ age_over_18: true });
    expect(result.issuer).toBe('https://issuer.example');
    expect(result.vct).toBe('urn:example:resident-card');
  });

  it('can reveal nothing, or everything', async () => {
    const credential = await issue();

    expect((await verify(await show(credential, []))).claims).toEqual({});
    expect((await verify(await show(credential, all))).claims).toEqual(claims);
  });

  it('refuses to reveal a claim the credential does not have', async () => {
    await expect(show(await issue(), ['height'])).rejects.toThrow(/height/);
  });
});

describe('verifying', () => {
  it('rejects a credential signed by someone else', async () => {
    const presentation = await show(await issue({ key: stranger }), ['age_over_18']);

    await expect(verify(presentation)).rejects.toThrow(/signature/);
  });

  it('rejects an expired credential', async () => {
    const presentation = await show(await issue(), ['age_over_18']);

    await expect(verify(presentation, { now: now + 3601 })).rejects.toThrow(/expired/);
  });

  it('rejects a claim that the issuer did not sign', async () => {
    const [jwt] = (await issue()).split('~');
    const forged = Buffer.from(JSON.stringify(['salt', 'age_over_18', true])).toString('base64url');

    await expect(verify(await show(`${jwt}~${forged}~`, ['age_over_18']))).rejects.toThrow(/disclosure/);
  });

  it('rejects a credential shown without proof of possession', async () => {
    await expect(verify(await issue())).rejects.toThrow(/key binding/);
  });

  it('rejects a presentation made with another wallet key', async () => {
    const presentation = await show(await issue(), ['age_over_18'], { key: stranger });

    await expect(verify(presentation)).rejects.toThrow(/key binding/);
  });

  it('rejects a presentation made for another request', async () => {
    const presentation = await show(await issue(), ['age_over_18']);

    await expect(verify(presentation, { nonce: 'n-2' })).rejects.toThrow(/nonce/);
    await expect(verify(presentation, { audience: 'someone-else' })).rejects.toThrow(/audience/);
  });

  it('rejects a presentation whose claims changed after it was signed', async () => {
    const parts = (await show(await issue(), ['age_over_18', 'given_name'])).split('~');
    parts.splice(1, 1);

    await expect(verify(parts.join('~'))).rejects.toThrow(/sd_hash/);
  });
});
