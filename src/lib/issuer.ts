import { decodeJwt, generateKey, randomId, verifyJwt } from './jose.ts';
import { json, type Handler } from './network.ts';
import { issueSdJwt, SD_JWT_VC, type Claims } from './sdjwt.ts';

export const PRE_AUTHORIZED = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
export const PROOF_TYPE = 'openid4vci-proof+jwt';

export interface CredentialType {
  vct: string;
  name: string;
  disclosable: string[];
}

export interface IssuerConfig {
  origin: string;
  name: string;
  credentials: Record<string, CredentialType>;
  tokenLifetime?: number;
}

export interface CredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants: Record<string, { 'pre-authorized_code': string }>;
}

export interface Issuer {
  origin: string;
  name: string;
  handle: Handler;
  offer(configuration: string, claims: Claims): { uri: string; offer: CredentialOffer };
}

interface Grant {
  configuration: string;
  claims: Claims;
}

const failure = (error: string, description: string, status = 400) =>
  json({ error, error_description: description }, status);

export async function createIssuer(config: IssuerConfig): Promise<Issuer> {
  const { origin, name, credentials, tokenLifetime = 300 } = config;
  const key = await generateKey();
  const codes = new Map<string, Grant>();
  const tokens = new Map<string, Grant & { expires: number }>();
  const nonces = new Set<string>();

  const metadata = {
    credential_issuer: origin,
    credential_endpoint: `${origin}/credential`,
    nonce_endpoint: `${origin}/nonce`,
    display: [{ name }],
    credential_configurations_supported: Object.fromEntries(
      Object.entries(credentials).map(([id, type]) => [
        id,
        {
          format: SD_JWT_VC,
          vct: type.vct,
          cryptographic_binding_methods_supported: ['jwk'],
          credential_signing_alg_values_supported: ['ES256'],
          proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
          credential_metadata: { display: [{ name: type.name }] },
        },
      ]),
    ),
  };

  async function token(request: Request) {
    const form = new URLSearchParams(await request.text());
    if (form.get('grant_type') !== PRE_AUTHORIZED) {
      return failure('unsupported_grant_type', 'only the pre-authorized code grant is supported');
    }
    const code = form.get('pre-authorized_code') ?? '';
    const grant = codes.get(code);
    if (!grant) return failure('invalid_grant', 'unknown or used pre-authorized code');
    codes.delete(code);

    const accessToken = randomId(32);
    tokens.set(accessToken, { ...grant, expires: Date.now() + tokenLifetime * 1000 });
    return json({ access_token: accessToken, token_type: 'Bearer', expires_in: tokenLifetime });
  }

  function nonce() {
    const value = randomId();
    nonces.add(value);
    return json({ c_nonce: value });
  }

  async function credential(request: Request) {
    const bearer = request.headers.get('authorization')?.match(/^Bearer (.+)$/)?.[1] ?? '';
    const grant = tokens.get(bearer);
    if (!grant || grant.expires < Date.now()) {
      return json({ error: 'invalid_token' }, 401, { 'www-authenticate': 'Bearer error="invalid_token"' });
    }

    const body = await request.json().catch(() => ({}));
    const type = credentials[grant.configuration];
    if (body.credential_configuration_id !== grant.configuration) {
      return failure('unknown_credential_configuration', 'the access token is not valid for this credential');
    }

    const proof = body.proofs?.jwt?.[0];
    if (typeof proof !== 'string') return failure('invalid_proof', 'a jwt proof is required');
    let holderJwk;
    let claims;
    try {
      holderJwk = decodeJwt(proof).header.jwk;
      const verified = await verifyJwt(proof, holderJwk);
      if (verified.header.typ !== PROOF_TYPE) throw new Error('wrong type');
      claims = verified.payload;
    } catch {
      return failure('invalid_proof', 'the proof is not a valid key proof');
    }
    if (claims.aud !== origin) return failure('invalid_proof', 'the proof was made for another issuer');
    if (!nonces.delete(claims.nonce)) return failure('invalid_nonce', 'unknown or used nonce');

    const issued = await issueSdJwt({
      issuer: origin,
      vct: type.vct,
      claims: grant.claims,
      disclosable: type.disclosable,
      holderJwk,
      key,
    });
    return json({ credentials: [{ credential: issued }] });
  }

  const handle: Handler = async (request) => {
    const route = `${request.method} ${new URL(request.url).pathname}`;
    switch (route) {
      case 'GET /.well-known/openid-credential-issuer':
        return json(metadata);
      case 'GET /.well-known/oauth-authorization-server':
        return json({
          issuer: origin,
          token_endpoint: `${origin}/token`,
          grant_types_supported: [PRE_AUTHORIZED],
          'pre-authorized_grant_anonymous_access_supported': true,
        });
      case 'GET /.well-known/jwt-vc-issuer':
        return json({ issuer: origin, jwks: { keys: [{ ...key.publicJwk, kid: key.kid, alg: 'ES256', use: 'sig' }] } });
      case 'POST /token':
        return token(request);
      case 'POST /nonce':
        return nonce();
      case 'POST /credential':
        return credential(request);
      default:
        return json({ error: 'not_found' }, 404);
    }
  };

  return {
    origin,
    name,
    handle,
    offer(configuration, claims) {
      if (!credentials[configuration]) throw new Error(`unknown credential "${configuration}"`);
      const code = randomId(32);
      codes.set(code, { configuration, claims });
      const offer: CredentialOffer = {
        credential_issuer: origin,
        credential_configuration_ids: [configuration],
        grants: { [PRE_AUTHORIZED]: { 'pre-authorized_code': code } },
      };
      return { offer, uri: `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}` };
    },
  };
}
