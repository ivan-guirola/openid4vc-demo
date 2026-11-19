import { afterAll, beforeAll, expect, it } from 'vitest';
import { createIssuer, type Issuer } from './lib/issuer.ts';
import { createVerifier, type Verifier } from './lib/verifier.ts';
import { createWallet } from './lib/wallet.ts';
import { serve, type Served } from './server.ts';

const card = { vct: 'urn:example:resident-card', name: 'Resident card', disclosable: ['given_name', 'age_over_18'] };

let issuerServer: Served;
let verifierServer: Served;
let issuer: Issuer;
let verifier: Verifier;

beforeAll(async () => {
  issuerServer = await serve((request) => issuer.handle(request));
  verifierServer = await serve((request) => verifier.handle(request));
  issuer = await createIssuer({ origin: issuerServer.origin, name: 'City Hall', credentials: { 'resident-card': card } });
  verifier = createVerifier({
    origin: verifierServer.origin,
    name: 'Cinema',
    trustedIssuers: [issuerServer.origin],
    fetch,
  });
});

afterAll(async () => {
  await Promise.all([issuerServer.close(), verifierServer.close()]);
});

it('issues and verifies a credential over real HTTP', async () => {
  const wallet = createWallet({ fetch });
  await wallet.receive(issuer.offer('resident-card', { given_name: 'Ana', age_over_18: true }).uri);
  const { uri, state } = verifier.request({ id: 'card', vct: card.vct, claims: ['age_over_18'] });

  const outcome = await wallet.answer(wallet.read(uri), 0, ['age_over_18']);

  expect(outcome.accepted).toBe(true);
  expect(verifier.result(state)).toEqual({ valid: true, issuer: issuerServer.origin, claims: { age_over_18: true } });
});

it('serves the issuer metadata as JSON', async () => {
  const response = await fetch(`${issuerServer.origin}/.well-known/openid-credential-issuer`);

  expect(response.headers.get('content-type')).toMatch(/application\/json/);
  expect((await response.json()).credential_issuer).toBe(issuerServer.origin);
});
