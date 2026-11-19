import type { PublicJwk } from './jose.ts';
import { randomId } from './jose.ts';
import { json, type Fetch, type Handler } from './network.ts';
import { SD_JWT_VC, verifyPresentation, type Claims } from './sdjwt.ts';

export interface Ask {
  id: string;
  vct: string;
  claims: string[];
}

export type Result = { valid: true; issuer: string; claims: Claims } | { valid: false; reason: string };

export interface VerifierConfig {
  origin: string;
  name: string;
  trustedIssuers: string[];
  fetch: Fetch;
}

export interface Verifier {
  origin: string;
  name: string;
  handle: Handler;
  request(ask: Ask): { uri: string; state: string };
  result(state: string): Result | undefined;
}

export function createVerifier({ origin, name, trustedIssuers, fetch }: VerifierConfig): Verifier {
  const responseUri = `${origin}/response`;
  const clientId = `redirect_uri:${responseUri}`;
  const pending = new Map<string, { nonce: string; ask: Ask }>();
  const results = new Map<string, Result>();

  async function issuerKey(issuer: string, kid: string | undefined): Promise<PublicJwk> {
    if (!trustedIssuers.includes(issuer)) throw new Error(`issuer ${issuer} is not trusted`);
    const response = await fetch(`${issuer}/.well-known/jwt-vc-issuer`);
    const keys: (PublicJwk & { kid?: string })[] = (await response.json()).jwks?.keys ?? [];
    const key = keys.find((candidate) => candidate.kid === kid) ?? (kid ? undefined : keys[0]);
    if (!key) throw new Error(`issuer ${issuer} has no key "${kid}"`);
    return key;
  }

  async function check(token: string | null, nonce: string, ask: Ask): Promise<Result> {
    try {
      const presentation = JSON.parse(token ?? '{}')[ask.id]?.[0];
      if (typeof presentation !== 'string') throw new Error(`no presentation for "${ask.id}"`);
      const verified = await verifyPresentation(presentation, { audience: clientId, nonce, issuerKey });
      if (verified.vct !== ask.vct) throw new Error(`unexpected credential type ${verified.vct}`);
      const missing = ask.claims.filter((claim) => !(claim in verified.claims));
      if (missing.length > 0) throw new Error(`missing claim ${missing.join(', ')}`);
      return { valid: true, issuer: verified.issuer, claims: verified.claims };
    } catch (error) {
      return { valid: false, reason: error instanceof Error ? error.message : String(error) };
    }
  }

  const handle: Handler = async (request) => {
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/response') {
      return json({ error: 'not_found' }, 404);
    }
    const form = new URLSearchParams(await request.text());
    const state = form.get('state') ?? '';
    const open = pending.get(state);
    if (!open) return json({ error: 'invalid_request', error_description: 'unknown or already answered request' }, 400);
    pending.delete(state);

    const result = await check(form.get('vp_token'), open.nonce, open.ask);
    results.set(state, result);
    return result.valid ? json({}) : json({ error: 'invalid_request', error_description: result.reason }, 400);
  };

  return {
    origin,
    name,
    handle,
    request(ask) {
      const state = randomId();
      const nonce = randomId();
      pending.set(state, { nonce, ask });
      const params = new URLSearchParams({
        response_type: 'vp_token',
        client_id: clientId,
        response_mode: 'direct_post',
        response_uri: responseUri,
        nonce,
        state,
        dcql_query: JSON.stringify({
          credentials: [
            {
              id: ask.id,
              format: SD_JWT_VC,
              meta: { vct_values: [ask.vct] },
              claims: ask.claims.map((claim) => ({ path: [claim] })),
            },
          ],
        }),
      });
      return { uri: `openid4vp://?${params}`, state };
    },
    result: (state) => results.get(state),
  };
}
