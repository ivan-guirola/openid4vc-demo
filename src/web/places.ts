import { decodeJwt, thumbprint, type PublicJwk } from '../lib/jose.ts';
import { describeCredential, type Card } from '../lib/inspect.ts';
import { code, definitions, fieldList, folded, json, make, pre } from './inside.ts';

type Label = (name: string) => string;
type Show = (value: unknown) => string;

function step(title: string, text: string, ...extra: HTMLElement[]) {
  const item = make('li');
  item.append(make('strong', title), make('p', text), ...extra);
  return item;
}

function stored(card: Card, credential: string) {
  const raw = make('pre', undefined, 'raw');
  card.jwt.split('.').forEach((part, index) => {
    if (index) raw.append('.');
    const span = make('span', part);
    span.dataset.kind = ['issuer-header', 'issuer-payload', 'issuer-signature'][index];
    raw.append(span);
  });
  for (const field of card.fields) {
    raw.append('~');
    const span = make('span', field.disclosure);
    span.dataset.kind = 'disclosure';
    raw.append(span);
  }
  if (credential.endsWith('~')) raw.append('~');
  return raw;
}

export interface IssuerDetail {
  credential: string;
  proof: string | undefined;
  issuerJwk: PublicJwk & { kid?: string };
  keysUrl: string;
  label: Label;
}

export async function renderIssuerDetail(root: HTMLElement, data: IssuerDetail) {
  const card = await describeCredential(data.credential);
  const url = new URL(data.keysUrl);
  const proof = data.proof ? decodeJwt(data.proof) : undefined;

  const salts = make('ul', undefined, 'mini');
  for (const field of card.fields) {
    const item = make('li');
    item.append(make('span', data.label(field.name)), code(`salt ${field.salt}`), code(`SHA-256 ${field.digest}`));
    salts.append(item);
  }

  const list = make('ol', undefined, 'did');
  list.append(
    step(
      'Checked that your wallet holds a key',
      'The wallet signed a short proof with its private key over a one-time number from City Hall. City Hall checked the signature with the public key that came inside the proof.',
      ...(proof ? [folded('The proof', pre(json(proof)))] : []),
    ),
    step(
      'Hid each field behind a fingerprint',
      'A random salt per field, then the SHA-256 of [salt, name, value]. Only the fingerprints go into what it signs.',
      salts,
    ),
    step(
      'Signed the card with its private key',
      `ES256 over the header and the content: who issued it, the type, the dates, your wallet’s public key (cnf) and the ${card.digests.length} fingerprints.`,
      definitions([['Key id', code(data.issuerJwk.kid ?? '')]]),
      folded('What it signed', pre(json(card.issuer.header)), pre(json(card.issuer.payload))),
    ),
    step(
      'Published its public key',
      'Anyone can fetch it to check the signature. The private part never leaves City Hall.',
      definitions([['At', code(url.host + url.pathname)]]),
      folded('Public key', pre(json(data.issuerJwk))),
    ),
  );
  root.replaceChildren(make('h3', 'What City Hall did'), list);
  root.hidden = false;
}

export interface WalletDetail {
  credential: string;
  label: Label;
  show: Show;
}

export async function renderWalletDetail(root: HTMLElement, data: WalletDetail) {
  const card = await describeCredential(data.credential);
  const holder = card.issuer.payload.cnf?.jwk as PublicJwk | undefined;
  const fields = make('ul', undefined, 'fields');
  fieldList(
    fields,
    card.fields,
    card.digests.length,
    data.label,
    data.show,
    () => 'Hidden in the card',
    () => 'The disclosure stays in the wallet. Only if you share it can anyone match it with the fingerprint.',
  );

  root.replaceChildren(
    make('h3', 'What your wallet keeps'),
    definitions([
      ['Its key', 'ES256 (P-256), created in the wallet. The private part cannot be exported and is never sent.'],
      ['Thumbprint', code(holder ? await thumbprint(holder) : '')],
      ['The card', `City Hall’s signed part plus ${card.fields.length} disclosures, one per field. Only the wallet holds the disclosures.`],
    ]),
    make('p', 'Open a field to see its salt, disclosure and fingerprint.', 'note'),
    fields,
    folded(
      'The card as it is stored',
      make(
        'p',
        'The signed part, then each disclosure, joined by ~. Base64url is not encryption: anyone with this text could read it, but could not show it without the wallet’s key.',
        'note',
      ),
      stored(card, data.credential),
    ),
  );
  root.hidden = false;
}

export interface RequestDetail {
  uri: string;
  label: Label;
}

export function renderRequestDetail(root: HTMLElement, data: RequestDetail) {
  const params = new URLSearchParams(data.uri.slice(data.uri.indexOf('?') + 1));
  const query = JSON.parse(params.get('dcql_query') ?? '{}').credentials?.[0] ?? {};
  const asked = (query.claims ?? []).map((claim: { path: string[] }) => data.label(claim.path[0])).join(', ');
  const readable = [...params]
    .map(([name, value]) => `${name} = ${name === 'dcql_query' ? json(JSON.parse(value)) : value}`)
    .join('\n');

  root.replaceChildren(
    make('h3', 'What the cinema asked for'),
    definitions([
      ['Fields', asked],
      ['Card type', code(query.meta?.vct_values?.join(', ') ?? '')],
      ['One-time number', code(params.get('nonce') ?? '')],
      ['Calls itself', code(params.get('client_id') ?? '')],
      ['Answer to', code(params.get('response_uri') ?? '')],
    ]),
    make(
      'p',
      'The wallet has to sign its answer over this one-time number and this name, so it only works here and now. Real verifiers also sign the request so the wallet knows who is asking; this demo does not.',
      'note',
    ),
    folded('The request as the wallet receives it', pre(readable)),
  );
  root.hidden = false;
}
