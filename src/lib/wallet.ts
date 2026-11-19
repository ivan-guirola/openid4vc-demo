import { PRE_AUTHORIZED, PROOF_TYPE, type CredentialOffer } from './issuer.ts';
import { decodeJwt, generateKey, signJwt, type KeyPair } from './jose.ts';
import type { Fetch } from './network.ts';
import { parseSdJwt, present, type Claims } from './sdjwt.ts';

const HIDDEN = new Set(['iss', 'iat', 'nbf', 'exp', 'vct', 'cnf', 'status', '_sd', '_sd_alg']);

export interface StoredCredential {
  issuer: string;
  issuerName: string;
  name: string;
  vct: string;
  claims: Claims;
  disclosable: string[];
  raw: string;
}

export interface PresentationRequest {
  verifier: string;
  responseUri: string;
  nonce: string;
  state: string;
  queryId: string;
  requested: string[];
  matches: number[];
}

export interface Wallet {
  credentials: StoredCredential[];
  receive(offerUri: string): Promise<StoredCredential>;
  read(requestUri: string): PresentationRequest;
  answer(request: PresentationRequest, credential: number, reveal: string[]): Promise<{ accepted: boolean; reason?: string }>;
}

export function createProof(options: { key: KeyPair; audience: string; nonce: string; now?: number }) {
  return signJwt(
    { alg: 'ES256', typ: PROOF_TYPE, jwk: options.key.publicJwk },
    { aud: options.audience, iat: options.now ?? Math.floor(Date.now() / 1000), nonce: options.nonce },
    options.key,
  );
}

const query = (uri: string) => new URLSearchParams(uri.slice(uri.indexOf('?') + 1));

export function createWallet({ fetch }: { fetch: Fetch }): Wallet {
  const credentials: StoredCredential[] = [];
  let key: Promise<KeyPair> | undefined;
  const holderKey = () => (key ??= generateKey());

  async function call(url: string, init?: RequestInit) {
    const response = await fetch(url, init);
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`${body.error ?? response.status}: ${body.error_description ?? url}`);
    return body;
  }

  async function receive(offerUri: string) {
    const offer: CredentialOffer = JSON.parse(query(offerUri).get('credential_offer') ?? 'null');
    const code = offer?.grants?.[PRE_AUTHORIZED]?.['pre-authorized_code'];
    if (!code) throw new Error('the offer has no pre-authorized code');

    const issuer = offer.credential_issuer;
    const configuration = offer.credential_configuration_ids[0];
    const metadata = await call(`${issuer}/.well-known/openid-credential-issuer`);
    const server = await call(`${issuer}/.well-known/oauth-authorization-server`);
    const token = await call(server.token_endpoint, {
      method: 'POST',
      body: new URLSearchParams({ grant_type: PRE_AUTHORIZED, 'pre-authorized_code': code }),
    });
    const { c_nonce } = await call(metadata.nonce_endpoint, { method: 'POST' });
    const proof = await createProof({ key: await holderKey(), audience: issuer, nonce: c_nonce });
    const issued = await call(metadata.credential_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token.access_token}` },
      body: JSON.stringify({ credential_configuration_id: configuration, proofs: { jwt: [proof] } }),
    });

    const raw: string = issued.credentials[0].credential;
    const { jwt, disclosures } = parseSdJwt(raw);
    const { payload } = decodeJwt(jwt);
    const claims: Claims = {};
    for (const [name, value] of Object.entries(payload)) {
      if (!HIDDEN.has(name)) claims[name] = value;
    }
    for (const disclosure of disclosures) claims[disclosure.name] = disclosure.value;

    const supported = metadata.credential_configurations_supported?.[configuration];
    const stored: StoredCredential = {
      issuer,
      issuerName: metadata.display?.[0]?.name ?? issuer,
      name: supported?.credential_metadata?.display?.[0]?.name ?? configuration,
      vct: payload.vct,
      claims,
      disclosable: disclosures.map((disclosure) => disclosure.name),
      raw,
    };
    credentials.push(stored);
    return stored;
  }

  function read(requestUri: string): PresentationRequest {
    const params = query(requestUri);
    const wanted = JSON.parse(params.get('dcql_query') ?? '{}').credentials?.[0];
    if (params.get('response_mode') !== 'direct_post' || !wanted) throw new Error('unsupported presentation request');

    const types: string[] = wanted.meta?.vct_values ?? [];
    return {
      verifier: params.get('client_id') ?? '',
      responseUri: params.get('response_uri') ?? '',
      nonce: params.get('nonce') ?? '',
      state: params.get('state') ?? '',
      queryId: wanted.id,
      requested: (wanted.claims ?? []).map((claim: { path: string[] }) => claim.path[0]),
      matches: credentials.flatMap((credential, index) => (types.includes(credential.vct) ? [index] : [])),
    };
  }

  async function answer(request: PresentationRequest, credential: number, reveal: string[]) {
    const presentation = await present(credentials[credential].raw, reveal, {
      audience: request.verifier,
      nonce: request.nonce,
      key: await holderKey(),
    });
    const response = await fetch(request.responseUri, {
      method: 'POST',
      body: new URLSearchParams({
        vp_token: JSON.stringify({ [request.queryId]: [presentation] }),
        state: request.state,
      }),
    });
    const body = await response.json().catch(() => ({}));
    return response.ok ? { accepted: true } : { accepted: false, reason: body.error_description };
  }

  return { credentials, receive, read, answer };
}
