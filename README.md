# OpenID4VC demo: verifiable credentials with SD-JWT

[![CI](https://github.com/ivan-guirola/openid4vc-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/ivan-guirola/openid4vc-demo/actions/workflows/ci.yml)

An issuer, a wallet and a verifier for verifiable credentials, written in TypeScript with no runtime dependencies.

**[Try it in your browser](https://ivan-guirola.github.io/openid4vc-demo/)**: City Hall issues a resident card, the wallet keeps it, and a cinema learns that the holder is an adult without seeing the name or the date of birth.

## What it implements

| Part | Specification | Implemented here |
| --- | --- | --- |
| Issuance | OpenID for Verifiable Credential Issuance 1.0 | Credential offer, pre-authorized code grant, nonce endpoint, credential endpoint with a `jwt` key proof |
| Presentation | OpenID for Verifiable Presentations 1.0 | Request with a DCQL query, `direct_post` response, `redirect_uri` client identifier prefix |
| Credential | SD-JWT and SD-JWT VC (`dc+sd-jwt`) | Selective disclosure of top-level claims, key binding, issuer keys from `/.well-known/jwt-vc-issuer` |

Signatures are ES256 through the Web Crypto API.

It is a teaching implementation, not a conformant product. The parts it leaves out: the authorization code flow, transaction codes, signed or encrypted presentation requests, nested and array disclosures, credential status and wallet attestation.

## How it is built

The issuer and the verifier are plain functions from `Request` to `Response`. That lets the same code run in two places:

- **In the browser**, mounted on an in-memory network (`src/lib/network.ts`) that also records every message for the demo page.
- **Over HTTP**, served by Node (`src/server.ts`).

```
src/lib/jose.ts       keys, JWT signing and verification
src/lib/sdjwt.ts      issue, present and verify SD-JWT credentials
src/lib/issuer.ts     OpenID4VCI endpoints
src/lib/verifier.ts   OpenID4VP request and response
src/lib/wallet.ts     receives credentials and answers requests
src/web/              the demo page
```

## Run it

```
npm install
npm run dev      # the demo page
npm test         # unit tests and a full flow over real HTTP
npm run serve    # issuer on :4001 and verifier on :4002
```

`npm run serve` needs Node 24 or later, which runs TypeScript directly.

## What the verifier checks

1. The issuer is one it trusts, and the credential carries its signature.
2. The credential has not expired.
3. Every disclosed claim matches a digest signed by the issuer.
4. The presentation is signed with the key the credential was issued to.
5. The presentation was made for this verifier and this request (audience and nonce), and its disclosures were not changed afterwards.
6. The claims it asked for are present.

Each one has a test that makes it fail.

## Disclaimer

This project was created for educational purposes or to support my day-to-day work.

## License

MIT
