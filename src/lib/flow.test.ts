import { beforeEach, describe, expect, it } from 'vitest';
import { createIssuer, type Issuer } from './issuer.ts';
import { generateKey } from './jose.ts';
import { createNetwork, type Network } from './network.ts';
import { createVerifier, type Verifier } from './verifier.ts';
import { createProof, createWallet, type Wallet } from './wallet.ts';

const CITY = 'https://cityhall.example';
const CINEMA = 'https://cinema.example';
const card = {
  vct: 'urn:example:resident-card',
  name: 'Resident card',
  disclosable: ['given_name', 'family_name', 'birthdate', 'locality', 'age_over_18'],
};
const ana = { given_name: 'Ana', family_name: 'García', birthdate: '1990-04-12', locality: 'Barcelona', age_over_18: true };
const ask = { id: 'card', vct: card.vct, claims: ['age_over_18'] };

let net: Network;
let issuer: Issuer;
let verifier: Verifier;
let wallet: Wallet;

beforeEach(async () => {
  net = createNetwork();
  issuer = await createIssuer({ origin: CITY, name: 'City Hall', credentials: { 'resident-card': card } });
  verifier = createVerifier({ origin: CINEMA, name: 'Cinema', trustedIssuers: [CITY], fetch: net.fetch });
  wallet = createWallet({ fetch: net.fetch });
  net.mount(CITY, issuer.handle);
  net.mount(CINEMA, verifier.handle);
});

const json = async (response: Response) => ({ status: response.status, body: await response.json() });
const form = (url: string, fields: Record<string, string>) =>
  net.fetch(url, { method: 'POST', body: new URLSearchParams(fields) });

async function accessToken() {
  const { offer } = issuer.offer('resident-card', ana);
  const grant = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  const response = await form(`${CITY}/token`, {
    grant_type: grant,
    'pre-authorized_code': offer.grants[grant]['pre-authorized_code'],
  });
  return (await response.json()).access_token as string;
}

const requestCredential = (token: string | undefined, proof: string) =>
  net.fetch(`${CITY}/credential`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ credential_configuration_id: 'resident-card', proofs: { jwt: [proof] } }),
  });

const nonce = async () => (await (await net.fetch(`${CITY}/nonce`, { method: 'POST' })).json()).c_nonce as string;

describe('issuer', () => {
  it('publishes what it issues and where', async () => {
    const { status, body } = await json(await net.fetch(`${CITY}/.well-known/openid-credential-issuer`));

    expect(status).toBe(200);
    expect(body).toMatchObject({
      credential_issuer: CITY,
      credential_endpoint: `${CITY}/credential`,
      nonce_endpoint: `${CITY}/nonce`,
      credential_configurations_supported: { 'resident-card': { format: 'dc+sd-jwt', vct: card.vct } },
    });
  });

  it('publishes its token endpoint and its signing keys', async () => {
    const server = await json(await net.fetch(`${CITY}/.well-known/oauth-authorization-server`));
    const keys = await json(await net.fetch(`${CITY}/.well-known/jwt-vc-issuer`));

    expect(server.body.token_endpoint).toBe(`${CITY}/token`);
    expect(keys.body.issuer).toBe(CITY);
    expect(keys.body.jwks.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(keys.body.jwks.keys[0].d).toBeUndefined();
  });

  it('offers a credential with a pre-authorized code', () => {
    const { uri, offer } = issuer.offer('resident-card', ana);

    expect(uri).toMatch(/^openid-credential-offer:\/\/\?credential_offer=/);
    expect(offer.credential_issuer).toBe(CITY);
    expect(offer.credential_configuration_ids).toEqual(['resident-card']);
    expect(offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']).toBeTruthy();
  });

  it('refuses an unknown code and an unknown grant', async () => {
    const wrongCode = await json(
      await form(`${CITY}/token`, {
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': 'nope',
      }),
    );
    const wrongGrant = await json(await form(`${CITY}/token`, { grant_type: 'password' }));

    expect(wrongCode).toMatchObject({ status: 400, body: { error: 'invalid_grant' } });
    expect(wrongGrant).toMatchObject({ status: 400, body: { error: 'unsupported_grant_type' } });
  });

  it('refuses a credential request without a valid access token', async () => {
    const key = await generateKey();
    const proof = await createProof({ key, audience: CITY, nonce: await nonce() });

    expect((await requestCredential(undefined, proof)).status).toBe(401);
    expect((await requestCredential('made-up', proof)).status).toBe(401);
  });

  it('refuses a proof with a nonce it did not give, or used before', async () => {
    const key = await generateKey();
    const token = await accessToken();
    const fresh = await nonce();

    const invented = await json(await requestCredential(token, await createProof({ key, audience: CITY, nonce: 'x' })));
    const first = await requestCredential(token, await createProof({ key, audience: CITY, nonce: fresh }));
    const again = await json(await requestCredential(token, await createProof({ key, audience: CITY, nonce: fresh })));

    expect(invented).toMatchObject({ status: 400, body: { error: 'invalid_nonce' } });
    expect(first.status).toBe(200);
    expect(again).toMatchObject({ status: 400, body: { error: 'invalid_nonce' } });
  });

  it('refuses a proof made for another issuer', async () => {
    const key = await generateKey();
    const proof = await createProof({ key, audience: 'https://other.example', nonce: await nonce() });

    expect(await json(await requestCredential(await accessToken(), proof))).toMatchObject({
      status: 400,
      body: { error: 'invalid_proof' },
    });
  });

  it('answers 404 to anything else', async () => {
    expect((await net.fetch(`${CITY}/nothing`)).status).toBe(404);
  });
});

describe('wallet', () => {
  it('receives a credential from an offer', async () => {
    const stored = await wallet.receive(issuer.offer('resident-card', ana).uri);

    expect(wallet.credentials).toEqual([stored]);
    expect(stored).toMatchObject({ issuer: CITY, issuerName: 'City Hall', name: 'Resident card', vct: card.vct });
    expect(stored.claims).toEqual(ana);
    expect(stored.disclosable.sort()).toEqual([...card.disclosable].sort());
  });

  it('cannot use the same offer twice', async () => {
    const { uri } = issuer.offer('resident-card', ana);
    await wallet.receive(uri);

    await expect(wallet.receive(uri)).rejects.toThrow(/invalid_grant/);
    expect(wallet.credentials).toHaveLength(1);
  });

  it('reads what a verifier asks for', async () => {
    await wallet.receive(issuer.offer('resident-card', ana).uri);
    const request = wallet.read(verifier.request(ask).uri);

    expect(request.verifier).toBe(`redirect_uri:${CINEMA}/response`);
    expect(request.requested).toEqual(['age_over_18']);
    expect(request.matches).toEqual([0]);
  });

  it('finds no match when it holds nothing of that type', () => {
    expect(wallet.read(verifier.request(ask).uri).matches).toEqual([]);
  });
});

describe('verifier', () => {
  it('asks for a presentation with a direct post back', () => {
    const { uri, state } = verifier.request(ask);
    const params = new URL(uri).searchParams;

    expect(uri).toMatch(/^openid4vp:\/\/\?/);
    expect(params.get('response_type')).toBe('vp_token');
    expect(params.get('response_mode')).toBe('direct_post');
    expect(params.get('response_uri')).toBe(`${CINEMA}/response`);
    expect(params.get('state')).toBe(state);
    expect(params.get('nonce')).toBeTruthy();
    expect(JSON.parse(params.get('dcql_query')!)).toEqual({
      credentials: [
        { id: 'card', format: 'dc+sd-jwt', meta: { vct_values: [card.vct] }, claims: [{ path: ['age_over_18'] }] },
      ],
    });
    expect(verifier.result(state)).toBeUndefined();
  });

  it('accepts the answer and learns only what was shared', async () => {
    await wallet.receive(issuer.offer('resident-card', ana).uri);
    const { uri, state } = verifier.request(ask);

    const outcome = await wallet.answer(wallet.read(uri), 0, ['age_over_18']);

    expect(outcome.accepted).toBe(true);
    expect(verifier.result(state)).toEqual({
      valid: true,
      issuer: CITY,
      claims: { age_over_18: true },
    });
  });

  it('rejects an answer that leaves out what it asked for', async () => {
    await wallet.receive(issuer.offer('resident-card', ana).uri);
    const { uri, state } = verifier.request(ask);

    const outcome = await wallet.answer(wallet.read(uri), 0, ['given_name']);

    expect(outcome.accepted).toBe(false);
    expect(verifier.result(state)).toMatchObject({ valid: false, reason: expect.stringMatching(/age_over_18/) });
  });

  it('rejects a credential from an issuer it does not trust', async () => {
    const other = await createIssuer({ origin: 'https://other.example', name: 'Other', credentials: { 'resident-card': card } });
    net.mount(other.origin, other.handle);
    await wallet.receive(other.offer('resident-card', ana).uri);
    const { uri, state } = verifier.request(ask);

    await wallet.answer(wallet.read(uri), 0, ['age_over_18']);

    expect(verifier.result(state)).toMatchObject({ valid: false, reason: expect.stringMatching(/trusted/) });
  });

  it('rejects an answer replayed for another request', async () => {
    await wallet.receive(issuer.offer('resident-card', ana).uri);
    const first = verifier.request(ask);
    await wallet.answer(wallet.read(first.uri), 0, ['age_over_18']);
    const sent = net.log.find((entry) => entry.path === '/response')!;
    const second = verifier.request(ask);

    const replay = new URLSearchParams(sent.request);
    replay.set('state', second.state);
    const response = await net.fetch(`${CINEMA}/response`, { method: 'POST', body: replay });

    expect(response.status).toBe(400);
    expect(verifier.result(second.state)).toMatchObject({ valid: false, reason: expect.stringMatching(/nonce/) });
  });

  it('accepts only one answer per request', async () => {
    await wallet.receive(issuer.offer('resident-card', ana).uri);
    const request = wallet.read(verifier.request(ask).uri);
    await wallet.answer(request, 0, ['age_over_18']);

    expect((await wallet.answer(request, 0, ['age_over_18'])).accepted).toBe(false);
  });
});

describe('network', () => {
  it('records every message that travels', async () => {
    await wallet.receive(issuer.offer('resident-card', ana).uri);

    expect(net.log.map((entry) => `${entry.method} ${entry.origin}${entry.path} ${entry.status}`)).toEqual([
      `GET ${CITY}/.well-known/openid-credential-issuer 200`,
      `GET ${CITY}/.well-known/oauth-authorization-server 200`,
      `POST ${CITY}/token 200`,
      `POST ${CITY}/nonce 200`,
      `POST ${CITY}/credential 200`,
    ]);
    expect(net.log[2].request).toContain('pre-authorized_code');
    expect(JSON.parse(net.log[4].response).credentials[0].credential).toContain('~');
  });

  it('fails like a network when nobody answers at that address', async () => {
    await expect(net.fetch('https://nobody.example/')).rejects.toThrow(TypeError);
  });
});
