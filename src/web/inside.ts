import { decodeJwt, thumbprint, type PublicJwk } from '../lib/jose.ts';
import { inspect, tamper, type Check, type Field, type Inspection, type Part } from '../lib/inspect.ts';

export interface InsideData {
  credential: string;
  presentation: string;
  issuerJwk: PublicJwk & { kid?: string };
  issuerName: string;
  keysUrl: string;
  proof: string | undefined;
  nonce: string;
  audience: string;
  verifierName: string;
  label: (name: string) => string;
  show: (value: unknown) => string;
}

export const json = (value: unknown) => JSON.stringify(value, null, 2);

export function make<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string, className?: string) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

export const pre = (text: string) => make('pre', text);
export const code = (text: string) => make('code', text);

export function definitions(entries: [string, string | HTMLElement | (string | HTMLElement)[]][]) {
  const list = make('dl');
  for (const [term, value] of entries) {
    const row = make('div');
    const description = make('dd');
    description.append(...(Array.isArray(value) ? value : [value]));
    row.append(make('dt', term), description);
    list.append(row);
  }
  return list;
}

export function folded(summary: string, ...content: HTMLElement[]) {
  const details = make('details', undefined, 'tech');
  details.append(make('summary', summary), ...content);
  return details;
}

const CARD_CLAIMS: Record<string, string> = {
  iss: 'Who issued the card',
  iat: 'When it was issued, in seconds since 1970',
  exp: 'When it stops being valid',
  vct: 'What kind of card it is',
  cnf: 'The public key of the wallet it was issued to',
  _sd: 'The fingerprints of the hidden fields, sorted so their order gives nothing away',
  _sd_alg: 'The hash used for the fingerprints',
};

const PROOF_CLAIMS: Record<string, string> = {
  iat: 'When the wallet made this answer',
  aud: 'Who the answer is for',
  nonce: 'The one-time number the cinema asked for',
  sd_hash: 'The SHA-256 of everything before this proof, so nothing can be added or removed',
};

function claimNotes(payload: Record<string, unknown>, notes: Record<string, string>) {
  return definitions(Object.keys(payload).flatMap((name) => (notes[name] ? [[name, notes[name]] as [string, string]] : [])));
}

async function keys(root: HTMLElement, data: InsideData, result: Inspection) {
  const url = new URL(data.keysUrl);
  const holderThumbprint = result.holderJwk ? await thumbprint(result.holderJwk) : '';
  const proof = data.proof ? decodeJwt(data.proof) : undefined;

  const card = (title: string, role: string, entries: Parameters<typeof definitions>[0], ...extra: HTMLElement[]) => {
    const node = make('article', undefined, 'key');
    node.append(make('h4', title), make('p', role, 'role'), definitions(entries), ...extra);
    return node;
  };

  root.replaceChildren(
    card(
      data.issuerName,
      'Signs the card, once',
      [
        ['Key id (kid)', code(data.issuerJwk.kid ?? '')],
        ['Private part', 'Only at City Hall'],
        ['Public part', ['Published at ', code(url.host + url.pathname)]],
      ],
      folded('Public key', pre(json(data.issuerJwk))),
    ),
    card(
      'Your wallet',
      'Signs every answer',
      [
        ['Thumbprint', code(holderThumbprint)],
        ['Private part', 'Only in your wallet. It is never sent.'],
        ['Public part', ['Inside the card, as ', code('cnf.jwk')]],
      ],
      folded('Public key', pre(json(result.holderJwk))),
      ...(proof
        ? [
            folded(
              'How City Hall knew the key was yours',
              make(
                'p',
                'Before issuing, the wallet signed a short proof with this key over a one-time number from City Hall. City Hall checked it, and only then copied the public key into the card.',
                'note',
              ),
              pre(json(proof)),
            ),
          ]
        : []),
    ),
    card(data.verifierName, 'Checks, does not sign', [
      ['Calls itself', code(data.audience)],
      ['One-time number', code(data.nonce)],
      ['Keys it uses', 'City Hall’s public key and the one inside the card'],
    ]),
  );
}

function holds(table: HTMLElement, data: InsideData, result: Inspection) {
  const head = make('thead');
  const top = make('tr');
  for (const cell of ['', data.issuerName, 'Your wallet', data.verifierName]) top.append(make('th', cell));
  head.append(top);

  const body = make('tbody');
  const row = (label: string, cells: [string, 'yes' | 'no' | 'part'][]) => {
    const line = make('tr');
    const header = make('th', label);
    header.scope = 'row';
    line.append(header);
    for (const [text, state] of cells) {
      const cell = make('td', text);
      cell.dataset.has = state;
      line.append(cell);
    }
    body.append(line);
  };

  for (const field of result.fields) {
    row(`${data.label(field.name)}: ${data.show(field.value)}`, [
      ['Wrote it', 'yes'],
      ['Has it', 'yes'],
      field.shared ? ['Received it', 'yes'] : ['Only its fingerprint', 'part'],
    ]);
  }
  row('City Hall’s signature', [
    ['Made it', 'yes'],
    ['Has it', 'yes'],
    ['Received it', 'yes'],
  ]);
  row('City Hall’s private key', [
    ['Has it', 'yes'],
    ['No', 'no'],
    ['No', 'no'],
  ]);
  row('Your wallet’s private key', [
    ['No', 'no'],
    ['Has it', 'yes'],
    ['No', 'no'],
  ]);
  row('Your wallet’s public key', [
    ['Put it in the card', 'yes'],
    ['Has it', 'yes'],
    ['Received it in the card', 'yes'],
  ]);
  row('The one-time number', [
    ['No', 'no'],
    ['Signed it', 'yes'],
    ['Made it', 'yes'],
  ]);
  table.replaceChildren(head, body);
}

export function fieldList(
  list: HTMLElement,
  items: Field[],
  total: number,
  label: (name: string) => string,
  show: (value: unknown) => string,
  pill: (field: Field) => string,
  note: (field: Field) => string,
) {
  list.replaceChildren(
    ...items.map((field) => {
      const summary = make('summary');
      summary.append(make('span', label(field.name), 'name'), make('span', show(field.value), 'value'), make('span', pill(field), 'pill'));
      const chain = make('ol', undefined, 'chain');
      const step = (title: string, value: string) => {
        const node = make('li');
        node.append(make('span', title), pre(value));
        chain.append(node);
      };
      step('A random salt, chosen by City Hall', field.salt);
      step('Salt, name and value as JSON', JSON.stringify([field.salt, field.name, field.value]));
      step('Encoded as Base64url: this is the disclosure', field.disclosure);
      step('Its SHA-256, also in Base64url: the fingerprint', field.digest);
      step('Where it sits in the signed card', `_sd[${field.position}] of ${total}`);
      const details = make('details');
      details.append(summary, chain, make('p', note(field), 'note'));
      const item = make('li');
      item.dataset.shared = String(field.shared);
      item.append(details);
      return item;
    }),
  );
}

function fields(list: HTMLElement, data: InsideData, result: Inspection) {
  fieldList(
    list,
    result.fields,
    result.digests.length,
    data.label,
    data.show,
    (field) => (field.shared ? 'Sent to the cinema' : 'Stayed in your wallet'),
    (field) =>
      field.shared
        ? 'Your wallet sent the disclosure, so the cinema repeated the last two steps, found the fingerprint in the card and read the value.'
        : 'Your wallet kept the disclosure. The cinema sees this fingerprint in the card but has no way to open it.',
  );
}

export const PART_LABELS: Record<Part['kind'], string> = {
  'issuer-header': 'Card header',
  'issuer-payload': 'Card content',
  'issuer-signature': 'City Hall’s signature',
  disclosure: 'What you revealed',
  'kb-header': 'Proof header',
  'kb-payload': 'Proof content',
  'kb-signature': 'Your wallet’s signature',
};

export function parts(legend: HTMLElement, raw: HTMLElement, result: Pick<Inspection, 'parts' | 'keyBinding'>) {
  legend.replaceChildren(
    ...Object.entries(PART_LABELS).map(([kind, label]) => {
      const item = make('li', label);
      item.dataset.kind = kind;
      return item;
    }),
  );
  raw.replaceChildren();
  result.parts.forEach((part, index) => {
    if (index > 0) {
      const previous = result.parts[index - 1].kind;
      const sameJwt = part.kind !== 'disclosure' && previous !== 'disclosure' && previous.split('-')[0] === part.kind.split('-')[0];
      raw.append(sameJwt ? '.' : '~');
    }
    const span = make('span', part.text);
    span.dataset.kind = part.kind;
    raw.append(span);
  });
  if (!result.keyBinding) raw.append('~');
}

function decoded(root: HTMLElement, result: Inspection) {
  const section = (title: string, ...content: HTMLElement[]) => {
    const node = make('section');
    node.append(make('h4', title), ...content);
    return node;
  };
  const shared = result.fields.filter((field) => field.shared);
  root.replaceChildren(
    section(
      '1. The card, signed by City Hall',
      pre(json(result.issuer.header)),
      pre(json(result.issuer.payload)),
      claimNotes(result.issuer.payload, CARD_CLAIMS),
      make(
        'p',
        'The signature is 64 bytes, the r and s values of ECDSA on P-256, made with City Hall’s private key over the Base64url header, a dot and the Base64url content. Changing a single character breaks it.',
        'note',
      ),
    ),
    section(
      '2. What you revealed',
      ...(shared.length
        ? shared.map((field) => pre(`${field.disclosure}\n→ ${JSON.stringify([field.salt, field.name, field.value])}`))
        : [make('p', 'Nothing. The cinema got the card with every field still hidden.', 'note')]),
    ),
    section(
      '3. The proof from your wallet',
      pre(json(result.keyBinding?.header ?? {})),
      pre(json(result.keyBinding?.payload ?? {})),
      claimNotes(result.keyBinding?.payload ?? {}, PROOF_CLAIMS),
      make('p', 'Signed with your wallet’s private key, the other half of the public key inside the card.', 'note'),
    ),
  );
}

const longDate = (seconds: number) =>
  new Date(seconds * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

function checkText(check: Check, data: InsideData, result: Inspection): [string, string, string[]] {
  switch (check.id) {
    case 'issuer':
      return [
        `The card was signed by ${data.issuerName}`,
        'The cinema fetched City Hall’s public key by its kid and checked the ES256 signature over the card header and content.',
        [`kid ${data.issuerJwk.kid ?? ''}`],
      ];
    case 'expiry':
      return ['The card is still valid', 'Its expiry date is in the future.', [`exp ${check.actual} = ${longDate(Number(check.actual))}`]];
    case 'disclosure': {
      const field = result.fields.find((item) => item.name === check.name);
      return [
        `“${data.label(check.name ?? '')}” is part of the card`,
        'The cinema hashed what your wallet sent and looked for the result among the fingerprints City Hall signed.',
        [`SHA-256 ${check.actual}`, check.ok && field ? `found at _sd[${field.position}]` : 'not in _sd'],
      ];
    }
    case 'holder':
      return [
        'It comes from the wallet the card was issued to',
        'The proof is signed with the private key that pairs with the public key inside the card. Someone with a copy of the card but not the key cannot make it.',
        [],
      ];
    case 'nonce':
      return [
        'It was made for this purchase',
        'The proof carries the one-time number the cinema just asked for, so an old answer cannot be replayed.',
        [`asked ${check.expected}`, `got   ${check.actual}`],
      ];
    case 'audience':
      return [
        `It was made for the ${data.verifierName.toLowerCase()}`,
        'An answer made for another verifier would be rejected here, and this one would be rejected there.',
        [`asked ${check.expected}`, `got   ${check.actual}`],
      ];
    case 'sd_hash':
      return [
        'Nothing was added or removed on the way',
        'The cinema hashed the card and the disclosures as it received them and compared the result with the hash inside the signed proof.',
        [`in the proof ${check.expected}`, `computed     ${check.actual}`],
      ];
  }
}

function steps(list: HTMLElement, data: InsideData, result: Inspection) {
  list.replaceChildren(
    ...result.checks.map((check) => {
      const [title, text, values] = checkText(check, data, result);
      const item = make('li');
      item.dataset.ok = String(check.ok);
      item.append(make('strong', title), make('p', text));
      if (values.length) item.append(pre(values.join('\n')));
      return item;
    }),
  );
}

function forgedValue(value: unknown): unknown {
  if (typeof value === 'boolean') return !value;
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) return '2000-01-01';
  return 'Someone else';
}

function tampering(root: HTMLElement, data: InsideData, result: Inspection) {
  const find = (name: string) => root.querySelector<HTMLElement>(`[data-vc="${name}"]`)!;
  const output = find('tampered');
  const target = result.fields.find((field) => field.shared);
  output.hidden = true;
  find('tamper-block').hidden = !target;
  if (!target) return;

  const value = forgedValue(target.value);
  find('tamper-intro').textContent = `Your wallet sent “${data.label(target.name)}: ${data.show(target.value)}”. A dishonest wallet could keep the salt and change the value to “${data.show(value)}”. It cannot change City Hall’s signature.`;
  find('tamper').onclick = async () => {
    const forged = await tamper({
      credential: data.credential,
      presentation: data.presentation,
      issuerJwk: data.issuerJwk,
      nonce: data.nonce,
      audience: data.audience,
      name: target.name,
      value,
    });
    output.replaceChildren(
      definitions([
        ['Forged disclosure', code(forged.forged)],
        ['Its fingerprint', code(forged.digest)],
        ['In the signed card?', forged.found ? 'Yes' : 'No. City Hall never signed it.'],
      ]),
      make('p', forged.error ? `The cinema rejects it: ${forged.error}.` : 'The cinema accepts it.', 'verdict'),
    );
    output.hidden = false;
  };
}

export async function renderInside(root: HTMLElement, data: InsideData) {
  const find = (name: string) => document.querySelector<HTMLElement>(`[data-vc="${name}"]`)!;
  const result = await inspect({
    credential: data.credential,
    presentation: data.presentation,
    issuerJwk: data.issuerJwk,
    nonce: data.nonce,
    audience: data.audience,
  });
  await keys(find('keys'), data, result);
  holds(find('holds'), data, result);
  fields(find('fields'), data, result);
  for (const suffix of ['', '-full']) {
    parts(find(`legend${suffix}`), find(`parts${suffix}`), result);
    decoded(find(`decoded${suffix}`), result);
    steps(find(`steps${suffix}`), data, result);
  }
  tampering(root, data, result);
  root.hidden = false;
  find('received').hidden = false;
}
