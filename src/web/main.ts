import '@fontsource-variable/geist';
import '@fontsource-variable/bricolage-grotesque';
import '@fontsource-variable/geist-mono';
import './style.css';
import { createIssuer } from '../lib/issuer.ts';
import { createNetwork, type Entry } from '../lib/network.ts';
import { createVerifier, type Result } from '../lib/verifier.ts';
import { createWallet, type PresentationRequest, type StoredCredential } from '../lib/wallet.ts';
import { renderInside } from './inside.ts';
import { renderIssuerDetail, renderRequestDetail, renderWalletDetail } from './places.ts';

const CITY = 'https://cityhall.example';
const CINEMA = 'https://cinema.example';
const CARD = {
  vct: 'urn:example:resident-card',
  name: 'Resident card',
  disclosable: ['given_name', 'family_name', 'birthdate', 'locality', 'age_over_18'],
};

const labels: Record<string, string> = {
  given_name: 'First name',
  family_name: 'Family name',
  birthdate: 'Date of birth',
  locality: 'City',
  age_over_18: 'Over 18',
};

const steps: Record<string, string> = {
  '/.well-known/openid-credential-issuer': 'The wallet asks City Hall what it issues',
  '/.well-known/oauth-authorization-server': 'The wallet asks where to get access',
  '/token': 'The wallet swaps the offer code for access',
  '/nonce': 'The wallet asks for a one-time number',
  '/credential': 'The wallet proves it holds a key and receives the card',
  '/.well-known/jwt-vc-issuer': 'The cinema fetches the public key of City Hall',
  '/response': 'The wallet sends the cinema what you chose',
};

const el = <T extends HTMLElement>(name: string) => document.querySelector<T>(`[data-vc="${name}"]`)!;
const make = <K extends keyof HTMLElementTagNameMap>(tag: K, text?: string) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
};

const network = createNetwork();
const issuer = await createIssuer({ origin: CITY, name: 'City Hall', credentials: { 'resident-card': CARD } });
const verifier = createVerifier({ origin: CINEMA, name: 'Cinema', trustedIssuers: [CITY], fetch: network.fetch });
const wallet = createWallet({ fetch: network.fetch });
network.mount(CITY, issuer.handle);
network.mount(CINEMA, verifier.handle);

let pending: { request: PresentationRequest; state: string } | undefined;

function show(value: unknown): string {
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return new Date(`${value}T00:00:00`).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
  }
  return String(value);
}

function rows(list: HTMLElement, claims: Record<string, unknown>) {
  list.replaceChildren(
    ...Object.entries(claims).map(([name, value]) => {
      const row = make('div');
      row.append(make('dt', labels[name] ?? name), make('dd', show(value)));
      return row;
    }),
  );
}

function status(name: string, message: string, state: 'ok' | 'error' | '' = '') {
  const node = el(name);
  node.textContent = message;
  node.dataset.state = state;
}

function focus(place: 'issuer' | 'wallet' | 'verifier') {
  for (const name of ['issuer', 'wallet', 'verifier']) el(name).toggleAttribute('data-active', name === place);
}

function isAdult(birthdate: string) {
  const born = new Date(`${birthdate}T00:00:00`);
  const limit = new Date();
  limit.setFullYear(limit.getFullYear() - 18);
  return born <= limit;
}

function renderWallet() {
  const credential: StoredCredential | undefined = wallet.credentials[0];
  el('wallet-empty').hidden = !!credential;
  el('card').hidden = !credential;
  if (!credential) el('wallet-detail').hidden = true;
  el('ask').hidden = !pending;
  if (!credential) return;

  el('card-name').textContent = credential.name;
  el('card-issuer').textContent = credential.issuerName;
  rows(el('card-claims'), credential.claims);

  if (!pending) return;
  el('ask-who').textContent = verifier.name;
  el('ask-claims').replaceChildren(
    ...Object.keys(credential.claims).map((name) => {
      const asked = pending!.request.requested.includes(name);
      const label = make('label');
      const box = make('input');
      box.type = 'checkbox';
      box.name = 'reveal';
      box.value = name;
      box.checked = asked;
      label.append(box, make('span', labels[name] ?? name));
      if (asked) label.append(make('small', 'asked for'));
      return label;
    }),
  );
}

function renderResult(result: Result | undefined, shared: string[]) {
  const credential = wallet.credentials[0];
  if (!result?.valid) {
    const reason = result?.reason ?? 'no answer';
    const missing = reason.match(/^missing claim (.+)$/)?.[1];
    status(
      'verifier-status',
      missing
        ? `No ticket. The cinema did not get what it asked for: ${missing.split(', ').map((name) => labels[name] ?? name).join(', ')}.`
        : `No ticket. The cinema rejected the answer: ${reason}.`,
      'error',
    );
    el('result').hidden = true;
    return;
  }

  const adult = result.claims.age_over_18 === true;
  status('verifier-status', adult ? 'Ticket sold. Enjoy the film.' : 'No ticket. The card says you are under 18.', adult ? 'ok' : 'error');
  rows(el('learned'), result.claims);
  const unseen = Object.keys(credential.claims).filter((name) => !shared.includes(name));
  el('unseen').textContent = unseen.length > 0 ? unseen.map((name) => labels[name] ?? name).join(', ') : 'Nothing: you shared the whole card.';
  el('result').hidden = false;
}

function receivedToken(): string | undefined {
  const sent = network.log.findLast((entry) => entry.path === '/response')?.request;
  const value = sent && new URLSearchParams(sent).get('vp_token');
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value);
    if (typeof parsed === 'string') return parsed;
    return Object.values(parsed as Record<string, string[]>).flat()[0];
  } catch {
    return value;
  }
}

function logged(path: string) {
  return network.log.findLast((entry) => entry.path === path);
}

async function renderInsideToken(request: PresentationRequest) {
  const token = receivedToken();
  const credential = wallet.credentials[0];
  const keys = logged('/.well-known/jwt-vc-issuer');
  el('jump').hidden = !token;
  el('inside').hidden = true;
  el('received').hidden = true;
  if (!token || !credential || !keys) return;

  const issuerJwk = JSON.parse(keys.response).jwks.keys[0];
  const sent = logged('/credential')?.request;
  await renderInside(el('inside'), {
    credential: credential.raw,
    presentation: token,
    issuerJwk,
    issuerName: credential.issuerName,
    keysUrl: `${keys.origin}${keys.path}`,
    proof: sent ? JSON.parse(sent).proofs?.jwt?.[0] : undefined,
    nonce: request.nonce,
    audience: request.verifier,
    verifierName: verifier.name,
    label: (name) => labels[name] ?? name,
    show,
  });
}

function pretty(text: string) {
  if (!text) return '(empty)';
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return [...new URLSearchParams(text)].map(([name, value]) => `${name} = ${value}`).join('\n');
  }
}

function record(entry: Entry) {
  const item = make('li', steps[entry.path] ?? entry.path);
  const line = make('span', ` ${entry.method} ${new URL(entry.origin).host}${entry.path} → ${entry.status}`);
  const detail = make('details');
  detail.append(make('summary', 'Messages'), make('pre', `${pretty(entry.request)}\n\n${pretty(entry.response)}`));
  item.append(make('br'), line, detail);
  el('log').append(item);
  el('log-count').textContent = `(${network.log.length})`;
}

network.listen(record);

el<HTMLFormElement>('form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.currentTarget as HTMLFormElement)) as Record<string, string>;
  const offer = issuer.offer('resident-card', { ...data, age_over_18: isAdult(data.birthdate) });

  pending = undefined;
  wallet.credentials.length = 0;
  el('result').hidden = true;
  el('jump').hidden = true;
  el('inside').hidden = true;
  el('received').hidden = true;
  el('issuer-detail').hidden = true;
  el('request-detail').hidden = true;
  status('verifier-status', '');
  try {
    await wallet.receive(offer.uri);
    status('issuer-status', 'Card issued. It is now in your wallet.', 'ok');
    const credential = wallet.credentials[0];
    const published = await (await issuer.handle(new Request(`${CITY}/.well-known/jwt-vc-issuer`))).json();
    const sent = network.log.findLast((entry) => entry.path === '/credential')?.request;
    await Promise.all([
      renderIssuerDetail(el('issuer-detail'), {
        credential: credential.raw,
        proof: sent ? JSON.parse(sent).proofs?.jwt?.[0] : undefined,
        issuerJwk: published.jwks.keys[0],
        keysUrl: `${CITY}/.well-known/jwt-vc-issuer`,
        label: (name) => labels[name] ?? name,
      }),
      renderWalletDetail(el('wallet-detail'), { credential: credential.raw, label: (name) => labels[name] ?? name, show }),
    ]);
    focus('wallet');
  } catch (error) {
    status('issuer-status', `The card could not be issued: ${(error as Error).message}`, 'error');
  }
  renderWallet();
});

el('buy').addEventListener('click', () => {
  const { uri, state } = verifier.request({ id: 'card', vct: CARD.vct, claims: ['age_over_18'] });
  const request = wallet.read(uri);
  el('result').hidden = true;
  if (request.matches.length === 0) {
    status('verifier-status', 'Your wallet has no resident card yet. Ask City Hall for one first.', 'error');
    focus('issuer');
    return;
  }
  el('jump').hidden = true;
  el('received').hidden = true;
  pending = { request, state };
  renderRequestDetail(el('request-detail'), { uri, label: (name) => labels[name] ?? name });
  status('verifier-status', 'Waiting for your wallet…');
  focus('wallet');
  renderWallet();
  el('ask').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
});

el<HTMLFormElement>('ask').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!pending) return;
  const { request, state } = pending;
  const shared = new FormData(event.currentTarget as HTMLFormElement).getAll('reveal') as string[];
  pending = undefined;

  await wallet.answer(request, request.matches[0], shared);
  renderWallet();
  renderResult(verifier.result(state), shared);
  await renderInsideToken(request);
  focus('verifier');
});

el('decline').addEventListener('click', () => {
  pending = undefined;
  renderWallet();
  el('jump').hidden = true;
  el('inside').hidden = true;
  el('received').hidden = true;
  status('verifier-status', 'You declined. The cinema learned nothing.');
  focus('verifier');
});

focus('issuer');
renderWallet();
